package com.example.blog.service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.blog.dto.AdminUserResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.dto.ReportResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.model.Post;
import com.example.blog.model.Role;
import com.example.blog.model.User;
import com.example.blog.repository.NotificationRepository;
import com.example.blog.repository.PostCommentRepository;
import com.example.blog.repository.PostLikeRepository;
import com.example.blog.repository.PostRepository;
import com.example.blog.repository.UserRepository;
import com.example.blog.repository.UserSubscriptionRepository;

/**
 * Administrative orchestration layer for moderation features such as reviewing
 * reports, banning/unbanning users, and moderating posts. Wraps repository
 * calls with authorization checks and transactional guarantees.
 */
@Service
public class AdminService {

	private final UserRepository userRepository;
	private final PostRepository postRepository;
	private final PostService postService;
	private final PostLikeRepository postLikeRepository;
	private final PostCommentRepository postCommentRepository;
	private final UserSubscriptionRepository userSubscriptionRepository;
	private final NotificationRepository notificationRepository;
	private final ReportService reportService;

	public AdminService(UserRepository userRepository, PostRepository postRepository, PostService postService,
			PostLikeRepository postLikeRepository, PostCommentRepository postCommentRepository,
			UserSubscriptionRepository userSubscriptionRepository, NotificationRepository notificationRepository,
			ReportService reportService) {
		this.userRepository = userRepository;
		this.postRepository = postRepository;
		this.postService = postService;
		this.postLikeRepository = postLikeRepository;
		this.postCommentRepository = postCommentRepository;
		this.userSubscriptionRepository = userSubscriptionRepository;
		this.notificationRepository = notificationRepository;
		this.reportService = reportService;
	}

	/**
	 * Returns the full moderation queue. Only admins may invoke this method.
	 */
	@Transactional(readOnly = true)
	public List<ReportResponse> getReports(User admin) {
		ensureAdmin(admin);
		return reportService.getAllReports(admin);
	}
	
	/**
	 * Lists every account in the system with aggregate data so admins can review
	 * status, role, and post volume.
	 */
	@Transactional(readOnly = true)
	public List<AdminUserResponse> getUsers(User admin) {
		ensureAdmin(admin);
		return userRepository.findAll().stream()
				.map(user -> {
					AdminUserResponse response = new AdminUserResponse();
					response.setId(user.getId());
					response.setName(user.getName());
					response.setEmail(user.getEmail());
					response.setRole(user.getRole());
					response.setCreatedAt(user.getCreatedAt());
					response.setUpdatedAt(user.getUpdatedAt());
					response.setBanned(user.isBanned());
					response.setPostCount(postRepository.countByAuthorId(user.getId()));
					return response;
				})
				.collect(Collectors.toList());
	}

	/**
	 * Pulls every post (even hidden ones) for administrative inspection.
	 */
	@Transactional(readOnly = true)
	public List<PostResponse> getAllPosts(User admin) {
		ensureAdmin(admin);
		return postService.getAllPosts(admin);
	}

	/**
	 * Marks the specified report as resolved. Useful when an admin chooses to
	 * acknowledge a report without taking further action.
	 */
	@Transactional
	public ReportResponse resolveReport(UUID reportId, User admin) {
		ensureAdmin(admin);
		return reportService.resolveReport(reportId, admin);
	}

	/**
	 * Bans a non-admin user and resolves any active reports targeting them.
	 */
	@Transactional
	public void banUser(UUID targetUserId, User admin) {
		User target = getManagedUser(targetUserId);
		ensureAdmin(admin);
		if (target.getRole() == Role.ADMIN) {
			throw new BadRequestException("You cannot ban another administrator");
		}
		if (!target.isBanned()) {
			target.setBanned(true);
			userRepository.save(target);
		}
		reportService.resolveReportsForUser(targetUserId);
	}

	/**
	 * Restores access to a previously banned account.
	 */
	@Transactional
	public void unbanUser(UUID targetUserId, User admin) {
		User target = getManagedUser(targetUserId);
		ensureAdmin(admin);
		if (target.isBanned()) {
			target.setBanned(false);
			userRepository.save(target);
		}
	}

	/**
	 * Permanently deletes a user and all of their content/subscriptions,
	 * including any related reports and notifications.
	 */
	@Transactional
	public void removeUser(UUID targetUserId, User admin) {
		User target = getManagedUser(targetUserId);
		ensureAdmin(admin);
		if (target.getRole() == Role.ADMIN) {
			throw new BadRequestException("You cannot remove another administrator");
		}
		List<Post> posts = postRepository.findAllByAuthorIdOrderByCreatedAtDesc(target.getId());
		for (Post post : posts) {
			reportService.deleteReportsForPost(post.getId());
			postService.deletePost(post.getId(), admin);
		}
		postLikeRepository.deleteByUserId(target.getId());
		postCommentRepository.deleteByAuthorId(target.getId());
		userSubscriptionRepository.deleteBySubscriberId(target.getId());
		userSubscriptionRepository.deleteByTargetId(target.getId());
		notificationRepository.deleteByRecipientId(target.getId());
		notificationRepository.deleteByActorId(target.getId());
		reportService.deleteReportsForUser(target.getId());
		userRepository.delete(target);
	}

	/**
	 * Flags a post as hidden (soft delete) and resolves associated reports.
	 */
	@Transactional
	public PostResponse hidePost(UUID postId, User admin) {
		ensureAdmin(admin);
		PostResponse response = postService.setPostHidden(postId, true, admin);
		reportService.resolveReportsForPost(postId);
		return response;
	}

	/**
	 * Reverses `hidePost`, making the content visible again.
	 */
	@Transactional
	public PostResponse unhidePost(UUID postId, User admin) {
		ensureAdmin(admin);
		return postService.setPostHidden(postId, false, admin);
	}

	/**
	 * Hard-deletes a post along with any reports pointing to it.
	 */
	@Transactional
	public void deletePost(UUID postId, User admin) {
		ensureAdmin(admin);
		reportService.deleteReportsForPost(postId);
		postService.deletePost(postId, admin);
	}

	/**
	 * Guards all admin operations to ensure the caller is an authenticated admin.
	 */
	private void ensureAdmin(User user) {
		if (user == null) {
			throw new UnauthorizedException("Authentication required");
		}
		if (user.getRole() != Role.ADMIN) {
			throw new ForbiddenException("Administrator privileges required");
		}
	}

	/**
	 * Loads a user or throws a 404-style exception when the id is unknown.
	 */
	private User getManagedUser(UUID userId) {
		return userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User not found"));
	}
}
