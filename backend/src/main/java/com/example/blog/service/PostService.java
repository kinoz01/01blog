package com.example.blog.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.example.blog.dto.PostCommentResponse;
import com.example.blog.dto.PostMediaResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.MediaType;
import com.example.blog.model.Post;
import com.example.blog.model.PostComment;
import com.example.blog.model.PostLike;
import com.example.blog.model.PostMedia;
import com.example.blog.model.Role;
import com.example.blog.model.User;
import com.example.blog.repository.PostCommentRepository;
import com.example.blog.repository.PostLikeRepository;
import com.example.blog.repository.PostRepository;
import com.example.blog.repository.UserRepository;
import com.example.blog.repository.UserSubscriptionRepository;
import com.example.blog.repository.projection.PostMetric;
import com.example.blog.service.MediaStorageService.StoredMedia;

/**
 * Core business logic for creating, updating, viewing, and moderating posts.
 * Aggregates likes/comments, stores media, sends notifications, and enforces
 * access control rules.
 */
@Service
public class PostService {

	private static final int MAX_MEDIA = 10;
	private static final int MAX_TITLE_LENGTH = 120;
	private static final int MAX_POST_LENGTH = 6000;

	private final PostRepository postRepository;
	private final MediaStorageService mediaStorageService;
	private final PostLikeRepository postLikeRepository;
	private final PostCommentRepository postCommentRepository;
	private final UserSubscriptionRepository userSubscriptionRepository;
	private final NotificationService notificationService;
	private final UserRepository userRepository;

	public PostService(PostRepository postRepository, MediaStorageService mediaStorageService,
			PostLikeRepository postLikeRepository, PostCommentRepository postCommentRepository,
			UserSubscriptionRepository userSubscriptionRepository, NotificationService notificationService,
			UserRepository userRepository) {
		this.postRepository = postRepository;
		this.mediaStorageService = mediaStorageService;
		this.postLikeRepository = postLikeRepository;
		this.postCommentRepository = postCommentRepository;
		this.userSubscriptionRepository = userSubscriptionRepository;
		this.notificationService = notificationService;
		this.userRepository = userRepository;
	}

	/**
	 * Returns the chronological feed for the signed-in user by inspecting their
	 * subscriptions. Empty list when they follow no one.
	 */
	@Transactional(readOnly = true)
	public List<PostResponse> getFeed(User currentUser) {
		User user = requireAuthenticatedUser(currentUser);
		List<UUID> subscribedAuthorIds = userSubscriptionRepository.findTargetIdsBySubscriberId(user.getId());
		if (subscribedAuthorIds == null || subscribedAuthorIds.isEmpty()) {
			return List.of();
		}
		List<Post> posts = postRepository.findAllByAuthorIdInOrderByCreatedAtDesc(subscribedAuthorIds);
		return mapPosts(posts, user, false);
	}

	/**
	 * Lists all posts written by the requested author, filtered by what the
	 * `currentUser` is allowed to view.
	 */
	@Transactional(readOnly = true)
	public List<PostResponse> getPostsByAuthor(@NonNull UUID authorId, User currentUser) {
		List<Post> posts = postRepository.findAllByAuthorIdOrderByCreatedAtDesc(authorId);
		return mapPosts(posts, currentUser, false);
	}
	
	/**
	 * Admin-only endpoint that fetches every post, regardless of visibility.
	 */
	@Transactional(readOnly = true)
	public List<PostResponse> getAllPosts(User currentUser) {
		User admin = requireAuthenticatedUser(currentUser);
		if (!isAdmin(admin)) {
			throw new ForbiddenException("Administrator privileges required");
		}
		List<Post> posts = postRepository.findAllByOrderByCreatedAtDesc();
		return mapPosts(posts, admin, false);
	}
	
	/**
	 * Convenience method used for profile stats showing total posts per user.
	 */
	@Transactional(readOnly = true)
	public long countPostsByAuthor(@NonNull UUID authorId) {
		return postRepository.countByAuthorId(authorId);
	}

	/**
	 * Fetches a single post by id and verifies the viewer may see it (hidden
	 * posts are limited to admins or the author).
	 */
	@Transactional(readOnly = true)
	public PostResponse getPost(@NonNull UUID postId, User currentUser) {
		Post post = getPostOrThrow(postId);
		if (!canViewPost(post, currentUser)) {
			throw new ForbiddenException("You cannot view this post");
		}
		return mapPosts(List.of(post), currentUser, true).stream().findFirst()
				.orElseThrow(() -> new ResourceNotFoundException("Post not found"));
	}

	/**
	 * Creates a new post with optional media uploads and notifies subscribers of
	 * the author.
	 */
	@Transactional
	public PostResponse createPost(String title, String description, List<MultipartFile> files, User owner) {
		requireAuthenticatedUser(owner);
		String normalizedTitle = normalizeTitle(title);
		String normalizedDescription = normalizeDescription(description);
		List<MultipartFile> mediaFiles = normalizeFiles(files);
		if (mediaFiles.size() > MAX_MEDIA) {
			throw new BadRequestException("You can upload up to " + MAX_MEDIA + " media files per post");
		}
		Post post = new Post();
		post.setTitle(normalizedTitle);
		post.setDescription(normalizedDescription);
		post.setAuthor(owner);

		List<StoredMedia> storedMedia = storeMediaFiles(mediaFiles);
		for (StoredMedia stored : storedMedia) {
			PostMedia media = new PostMedia();
			media.setFileName(stored.fileName());
			media.setMimeType(stored.mimeType());
			media.setUrl(stored.url());
			media.setOriginalFileName(stored.originalFileName());
			media.setType(stored.mimeType().startsWith("video/") ? MediaType.VIDEO : MediaType.IMAGE);
			post.addMedia(media);
		}
		Post saved = postRepository.save(post);
		notifySubscribers(owner, saved);
		return mapPosts(List.of(saved), owner, false).get(0);
	}

	/**
	 * Updates an existing post's text and attachments. Callers can flag media for
	 * removal and upload additional files in the same operation.
	 */
	@Transactional
	public PostResponse updatePost(@NonNull UUID postId, String title, String description, List<UUID> removeMediaIds,
			List<MultipartFile> newMediaFiles, User currentUser) {
		User owner = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		ensureOwnership(post, owner);
		post.setTitle(normalizeTitle(title));
		post.setDescription(normalizeDescription(description));
		removeMedia(post, removeMediaIds);
		addMedia(post, newMediaFiles);
		Post saved = postRepository.save(post);
		return mapPosts(List.of(saved), owner, false).get(0);
	}

	/**
	 * Completely removes a post and any associated media/engagement data.
	 */
	@Transactional
	public void deletePost(@NonNull UUID postId, User currentUser) {
		User owner = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		ensureOwnership(post, owner);
		postLikeRepository.deleteByPostId(post.getId());
		postCommentRepository.deleteByPostId(post.getId());
		post.getMedia().forEach(media -> mediaStorageService.delete(media.getFileName()));
		postRepository.delete(post);
	}
	
	/**
	 * Admin utility to toggle a post's `hidden` flag.
	 */
	@Transactional
	public PostResponse setPostHidden(@NonNull UUID postId, boolean hidden, User currentUser) {
		User actor = requireAuthenticatedUser(currentUser);
		if (!isAdmin(actor)) {
			throw new ForbiddenException("Administrator privileges required");
		}
		Post post = getPostOrThrow(postId);
		post.setHidden(hidden);
		Post saved = postRepository.save(post);
		return mapPosts(List.of(saved), actor, false).get(0);
	}

	/**
	 * Registers a like for the requesting user if they are allowed to interact
	 * with the post.
	 */
	@Transactional
	public PostResponse likePost(@NonNull UUID postId, User currentUser) {
		User actor = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		if (!canViewPost(post, actor)) {
			throw new ForbiddenException("You cannot interact with this post");
		}
		if (!postLikeRepository.existsByPostIdAndUserId(post.getId(), actor.getId())) {
			PostLike like = new PostLike();
			like.setPost(post);
			like.setUser(actor);
			postLikeRepository.save(like);
		}
		return mapPosts(List.of(post), actor, false).get(0);
	}

	/**
	 * Removes a previously registered like.
	 */
	@Transactional
	public PostResponse unlikePost(@NonNull UUID postId, User currentUser) {
		User actor = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		if (!canViewPost(post, actor)) {
			throw new ForbiddenException("You cannot interact with this post");
		}
		postLikeRepository.deleteByPostIdAndUserId(post.getId(), actor.getId());
		return mapPosts(List.of(post), actor, false).get(0);
	}

	/**
	 * Adds a comment authored by the current user.
	 */
	@Transactional
	public PostCommentResponse addComment(@NonNull UUID postId, String content, User currentUser) {
		User author = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		if (!canViewPost(post, author)) {
			throw new ForbiddenException("You cannot interact with this post");
		}
		String normalizedContent = normalizeComment(content);
		PostComment comment = new PostComment();
		comment.setPost(post);
		comment.setAuthor(author);
		comment.setContent(normalizedContent);
		PostComment saved = postCommentRepository.save(comment);
		return mapComment(saved);
	}

	/**
	 * Deletes a comment when requested by its author or an admin.
	 */
	@Transactional
	public void deleteComment(@NonNull UUID postId, @NonNull UUID commentId, User currentUser) {
		User actor = requireAuthenticatedUser(currentUser);
		PostComment comment = postCommentRepository.findById(commentId)
				.orElseThrow(() -> new ResourceNotFoundException("Comment not found"));
		if (!comment.getPost().getId().equals(postId)) {
			throw new ResourceNotFoundException("Comment not found");
		}
		boolean isAuthor = comment.getAuthor().getId().equals(actor.getId());
		if (!isAuthor && !isAdmin(actor)) {
			throw new ForbiddenException("You cannot delete this comment");
		}
		postCommentRepository.delete(comment);
	}

	/**
	 * Maps a collection of Post entities into PostResponse DTOs, optionally
	 * embedding full comment threads.
	 */
	private List<PostResponse> mapPosts(List<Post> posts, User currentUser, boolean includeComments) {
		if (posts == null || posts.isEmpty()) {
			return List.of();
		}
		List<Post> visiblePosts = posts.stream()
				.filter(post -> canViewPost(post, currentUser))
				.collect(Collectors.toList());
		if (visiblePosts.isEmpty()) {
			return List.of();
		}
		List<UUID> postIds = visiblePosts.stream().map(Post::getId).collect(Collectors.toList());
		List<PostMetric> likeMetrics = postIds.isEmpty() ? List.of()
				: postLikeRepository.aggregateCountsByPostIds(postIds);
		List<PostMetric> commentMetrics = postIds.isEmpty() ? List.of()
				: postCommentRepository.aggregateCountsByPostIds(postIds);
		Map<UUID, Long> likeCounts = toMetricMap(likeMetrics);
		Map<UUID, Long> commentCounts = toMetricMap(commentMetrics);
		Set<UUID> likedPostIds = (currentUser == null || postIds.isEmpty())
				? Set.of()
				: new HashSet<>(postLikeRepository.findPostIdsLikedByUser(currentUser.getId(), postIds));
		Map<UUID, List<PostCommentResponse>> comments = includeComments ? mapCommentsByPost(postIds) : Map.of();

		return visiblePosts.stream().map(post -> {
			long likeCount = likeCounts.getOrDefault(post.getId(), 0L);
			long commentCount = commentCounts.getOrDefault(post.getId(), 0L);
			boolean likedByUser = currentUser != null && likedPostIds.contains(post.getId());
			List<PostCommentResponse> commentResponses = includeComments
					? comments.getOrDefault(post.getId(), List.of())
					: null;
			return buildPostResponse(post, likeCount, commentCount, likedByUser, commentResponses);
		}).collect(Collectors.toList());
	}

	/**
	 * Converts aggregated metrics (likes/comments) into a simple UUID -> count
	 * map for faster lookup when assembling responses.
	 */
	private Map<UUID, Long> toMetricMap(List<PostMetric> metrics) {
		Map<UUID, Long> map = new HashMap<>();
		if (metrics == null) {
			return map;
		}
		for (PostMetric metric : metrics) {
			map.put(metric.getPostId(), metric.getCount());
		}
		return map;
	}

	/**
	 * Loads and groups comments for the provided post ids so they can be attached
	 * to responses without multiple queries.
	 */
	private Map<UUID, List<PostCommentResponse>> mapCommentsByPost(List<UUID> postIds) {
		if (postIds == null || postIds.isEmpty()) {
			return Map.of();
		}
		List<PostComment> comments = postCommentRepository.findAllByPostIdInOrderByCreatedAtAsc(postIds);
		Map<UUID, List<PostCommentResponse>> grouped = new HashMap<>();
		for (PostComment comment : comments) {
			grouped.computeIfAbsent(comment.getPost().getId(), key -> new ArrayList<>()).add(mapComment(comment));
		}
		return grouped;
	}

	/**
	 * Assembles the final PostResponse DTO from the entity + metrics.
	 */
	private PostResponse buildPostResponse(Post post, long likeCount, long commentCount, boolean likedByUser,
			List<PostCommentResponse> comments) {
		PostResponse response = new PostResponse();
		response.setId(post.getId());
		response.setTitle(post.getTitle());
		response.setDescription(post.getDescription());
		response.setCreatedAt(post.getCreatedAt());
		response.setUpdatedAt(post.getUpdatedAt());
		PostResponse.AuthorSummary author = new PostResponse.AuthorSummary();
		author.setId(post.getAuthor().getId());
		author.setName(post.getAuthor().getName());
		author.setRole(post.getAuthor().getRole());
		response.setAuthor(author);
		List<PostMediaResponse> mediaResponses = post.getMedia().stream().map(media -> {
			PostMediaResponse m = new PostMediaResponse();
			m.setId(media.getId());
			m.setUrl(media.getUrl());
			m.setMimeType(media.getMimeType());
			m.setType(media.getType());
			m.setOriginalFileName(media.getOriginalFileName());
			return m;
		}).collect(Collectors.toList());
		response.setMedia(mediaResponses);
		response.setLikeCount(likeCount);
		response.setCommentCount(commentCount);
		response.setLikedByCurrentUser(likedByUser);
		response.setComments(comments);
		response.setHidden(post.isHidden());
		return response;
	}

	/**
	 * Converts a PostComment entity to its DTO counterpart.
	 */
	private PostCommentResponse mapComment(PostComment comment) {
		PostCommentResponse response = new PostCommentResponse();
		response.setId(comment.getId());
		response.setContent(comment.getContent());
		response.setCreatedAt(comment.getCreatedAt());
		response.setUpdatedAt(comment.getUpdatedAt());
		PostCommentResponse.AuthorSummary author = new PostCommentResponse.AuthorSummary();
		author.setId(comment.getAuthor().getId());
		author.setName(comment.getAuthor().getName());
		response.setAuthor(author);
		return response;
	}

	/**
	 * Validates and removes attachments flagged for deletion during an update.
	 */
	private void removeMedia(Post post, List<UUID> mediaIdsToRemove) {
		List<UUID> ids = mediaIdsToRemove == null ? List.of() : mediaIdsToRemove;
		if (ids.isEmpty()) {
			return;
		}
		Set<UUID> uniqueIds = ids.stream().filter(id -> id != null).collect(Collectors.toSet());
		if (uniqueIds.isEmpty()) {
			return;
		}
		List<PostMedia> mediaToRemove = post.getMedia().stream()
				.filter(media -> uniqueIds.contains(media.getId()))
				.collect(Collectors.toList());
		if (mediaToRemove.size() != uniqueIds.size()) {
			throw new BadRequestException("One or more attachments could not be removed");
		}
		for (PostMedia media : mediaToRemove) {
			post.getMedia().remove(media);
			mediaStorageService.delete(media.getFileName());
		}
	}

	/**
	 * Adds newly uploaded media files to an existing post.
	 */
	private void addMedia(Post post, List<MultipartFile> files) {
		List<MultipartFile> mediaFiles = normalizeFiles(files);
		if (mediaFiles.isEmpty()) {
			return;
		}
		if (post.getMedia().size() + mediaFiles.size() > MAX_MEDIA) {
			throw new BadRequestException("You can upload up to " + MAX_MEDIA + " media files per post");
		}
		List<StoredMedia> storedMedia = storeMediaFiles(mediaFiles);
		for (StoredMedia stored : storedMedia) {
			PostMedia media = new PostMedia();
			media.setFileName(stored.fileName());
			media.setMimeType(stored.mimeType());
			media.setUrl(stored.url());
			media.setOriginalFileName(stored.originalFileName());
			media.setType(stored.mimeType().startsWith("video/") ? MediaType.VIDEO : MediaType.IMAGE);
			post.addMedia(media);
		}
	}

	/**
	 * Filters null/empty uploads and returns a clean list for processing.
	 */
	private List<MultipartFile> normalizeFiles(List<MultipartFile> files) {
		if (files == null || files.isEmpty()) {
			return List.of();
		}
		return files.stream().filter(file -> file != null && !file.isEmpty()).collect(Collectors.toList());
	}

	/**
	 * Delegates to MediaStorageService to persist files and returns the stored
	 * metadata for later attachment to PostMedia entities.
	 */
	private List<StoredMedia> storeMediaFiles(Collection<MultipartFile> mediaFiles) {
		List<StoredMedia> storedMedia = new ArrayList<>();
		if (mediaFiles == null) {
			return storedMedia;
		}
		for (MultipartFile file : mediaFiles) {
			if (file == null || file.isEmpty()) {
				continue;
			}
			storedMedia.add(mediaStorageService.store(file));
		}
		return storedMedia;
	}

	/**
	 * Checks whether the given viewer has permission to see a post (even if
	 * hidden).
	 */
	private boolean canViewPost(Post post, User viewer) {
		if (post == null) {
			return false;
		}
		if (!post.isHidden()) {
			return true;
		}
		if (viewer == null) {
			return false;
		}
		return isAdmin(viewer) || post.getAuthor().getId().equals(viewer.getId());
	}

	/**
	 * Utility to check the ADMIN role without repeated null checks.
	 */
	private boolean isAdmin(User user) {
		return user != null && user.getRole() == Role.ADMIN;
	}

	/**
	 * Ensures titles are present and within the configured length limits.
	 */
	private String normalizeTitle(String rawTitle) {
		if (!StringUtils.hasText(rawTitle)) {
			throw new BadRequestException("Title is required");
		}
		String normalizedTitle = rawTitle.trim();
		if (normalizedTitle.length() > MAX_TITLE_LENGTH) {
			throw new BadRequestException("Title must be " + MAX_TITLE_LENGTH + " characters or fewer");
		}
		return normalizedTitle;
	}

	/**
	 * Cleans and validates the post body.
	 */
	private String normalizeDescription(String rawDescription) {
		if (!StringUtils.hasText(rawDescription)) {
			throw new BadRequestException("Post content is required");
		}
		String normalizedDescription = rawDescription.trim();
		if (normalizedDescription.length() > MAX_POST_LENGTH) {
			throw new BadRequestException("Post content must be " + MAX_POST_LENGTH + " characters or fewer");
		}
		return normalizedDescription;
	}

	/**
	 * Validates text for individual comments.
	 */
	private String normalizeComment(String rawComment) {
		if (!StringUtils.hasText(rawComment)) {
			throw new BadRequestException("Comment cannot be empty");
		}
		String normalizedComment = rawComment.trim();
		if (normalizedComment.length() > 1000) {
			throw new BadRequestException("Comments must be 1000 characters or fewer");
		}
		return normalizedComment;
	}

	/**
	 * Guards methods that require a logged-in, non-banned user.
	 */
	private User requireAuthenticatedUser(User owner) {
		if (owner == null) {
			throw new UnauthorizedException("Authentication required");
		}
		if (owner.isBanned()) {
			throw new ForbiddenException("You are not allowed to perform this action");
		}
		return owner;
	}

	/**
	 * Loads a post or throws a 404-style exception when missing.
	 */
	private Post getPostOrThrow(@NonNull UUID postId) {
		return postRepository.findById(postId).orElseThrow(() -> new ResourceNotFoundException("Post not found"));
	}

	/**
	 * Ensures the acting user either owns the post or is an admin; otherwise a
	 * forbidden error is raised.
	 */
	private void ensureOwnership(Post post, User user) {
		if (isAdmin(user)) {
			return;
		}
		if (!post.getAuthor().getId().equals(user.getId())) {
			throw new ForbiddenException("You can only modify your own posts");
		}
	}

	/**
	 * Notifies all subscribers that the author published a new post.
	 */
	private void notifySubscribers(User author, Post post) {
		List<UUID> subscriberIds = userSubscriptionRepository.findSubscriberIdsByTargetId(author.getId());
		if (subscriberIds == null || subscriberIds.isEmpty()) {
			return;
		}
		List<User> recipients = userRepository.findAllById(subscriberIds);
		UUID postId = post.getId();
		if (postId == null) {
			return;
		}
		for (User recipient : recipients) {
			if (recipient.getId().equals(author.getId())) {
				continue;
			}
			notificationService.notifyPostPublished(author, recipient, postId);
		}
	}
}
