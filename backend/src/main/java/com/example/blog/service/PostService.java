package com.example.blog.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.example.blog.dto.PostMediaResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.MediaType;
import com.example.blog.model.Post;
import com.example.blog.model.PostMedia;
import com.example.blog.model.User;
import com.example.blog.repository.PostRepository;
import com.example.blog.service.MediaStorageService.StoredMedia;

@Service
public class PostService {

	private static final int MAX_MEDIA = 10;
	private static final int MAX_TITLE_LENGTH = 120;
	private static final int MAX_POST_LENGTH = 6000;

	private final PostRepository postRepository;
	private final MediaStorageService mediaStorageService;

	public PostService(PostRepository postRepository, MediaStorageService mediaStorageService) {
		this.postRepository = postRepository;
		this.mediaStorageService = mediaStorageService;
	}

	@Transactional(readOnly = true)
	public List<PostResponse> getFeed() {
		return postRepository.findAllByOrderByCreatedAtDesc().stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	@Transactional(readOnly = true)
	public PostResponse getPost(UUID postId) {
		Post post = getPostOrThrow(postId);
		return mapToResponse(post);
	}

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
		return mapToResponse(saved);
	}

	@Transactional
	public PostResponse updatePost(UUID postId, String title, String description, List<UUID> removeMediaIds,
			List<MultipartFile> newMediaFiles, User currentUser) {
		User owner = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		ensureOwnership(post, owner);
		post.setTitle(normalizeTitle(title));
		post.setDescription(normalizeDescription(description));
		removeMedia(post, removeMediaIds);
		addMedia(post, newMediaFiles);
		Post saved = postRepository.save(post);
		return mapToResponse(saved);
	}

	@Transactional
	public void deletePost(UUID postId, User currentUser) {
		User owner = requireAuthenticatedUser(currentUser);
		Post post = getPostOrThrow(postId);
		ensureOwnership(post, owner);
		post.getMedia().forEach(media -> mediaStorageService.delete(media.getFileName()));
		postRepository.delete(post);
	}

	private PostResponse mapToResponse(Post post) {
		PostResponse response = new PostResponse();
		response.setId(post.getId());
		response.setTitle(post.getTitle());
		response.setDescription(post.getDescription());
		response.setCreatedAt(post.getCreatedAt());
		response.setUpdatedAt(post.getUpdatedAt());
		PostResponse.AuthorSummary author = new PostResponse.AuthorSummary();
		author.setId(post.getAuthor().getId());
		author.setName(post.getAuthor().getName());
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
		return response;
	}

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

	private List<MultipartFile> normalizeFiles(List<MultipartFile> files) {
		if (files == null || files.isEmpty()) {
			return List.of();
		}
		return files.stream().filter(file -> file != null && !file.isEmpty()).collect(Collectors.toList());
	}

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

	private User requireAuthenticatedUser(User owner) {
		if (owner == null) {
			throw new UnauthorizedException("Authentication required");
		}
		return owner;
	}

	private Post getPostOrThrow(UUID postId) {
		return postRepository.findById(postId).orElseThrow(() -> new ResourceNotFoundException("Post not found"));
	}

	private void ensureOwnership(Post post, User user) {
		if (!post.getAuthor().getId().equals(user.getId())) {
			throw new ForbiddenException("You can only modify your own posts");
		}
	}
}
