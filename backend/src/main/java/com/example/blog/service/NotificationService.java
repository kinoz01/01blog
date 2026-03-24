package com.example.blog.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.blog.dto.NotificationResponse;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.model.Notification;
import com.example.blog.model.User;
import com.example.blog.repository.NotificationRepository;

/**
 * Stores and manages user-to-user notifications (currently "post published"
 * events). Provides helpers for delivery, listing, marking as read, and delete.
 */
@Service
public class NotificationService {

	private final NotificationRepository notificationRepository;

	public NotificationService(NotificationRepository notificationRepository) {
		this.notificationRepository = notificationRepository;
	}

	/**
	 * Persists a notification informing `recipient` that `actor` published a new
	 * post. Self-notifications are ignored.
	 */
	@Transactional
	public void notifyPostPublished(User actor, User recipient, @NonNull UUID postId) {
		if (recipient == null || actor == null || recipient.getId().equals(actor.getId())) {
			return;
		}
		Notification notification = new Notification();
		notification.setActor(actor);
		notification.setRecipient(recipient);
		notification.setPostId(postId);
		notification.setMessage(actor.getName() + " published a new post.");
		notificationRepository.save(notification);
	}

	/**
	 * Returns all notifications for the given user, newest first.
	 */
	@Transactional(readOnly = true)
	public List<NotificationResponse> getNotifications(@NonNull User user) {
		return notificationRepository.findByRecipientIdOrderByCreatedAtDesc(user.getId()).stream()
				.map(this::mapToResponse)
				.collect(Collectors.toList());
	}

	/**
	 * Marks a single notification as read, enforcing ownership.
	 */
	@Transactional
	public void markAsRead(@NonNull User user, @NonNull UUID notificationId) {
		Notification notification = notificationRepository.findById(notificationId)
				.orElseThrow(() -> new ResourceNotFoundException("Notification not found"));
		if (!notification.getRecipient().getId().equals(user.getId())) {
			throw new ForbiddenException("You cannot modify this notification");
		}
		if (notification.getReadAt() == null) {
			notification.setReadAt(Instant.now());
			notificationRepository.save(notification);
		}
	}

	/**
	 * Hard-deletes a notification the current user owns.
	 */
	@Transactional
	public void delete(@NonNull User user, @NonNull UUID notificationId) {
		Notification notification = notificationRepository.findById(notificationId)
				.orElseThrow(() -> new ResourceNotFoundException("Notification not found"));
		if (!notification.getRecipient().getId().equals(user.getId())) {
			throw new ForbiddenException("You cannot modify this notification");
		}
		notificationRepository.delete(notification);
	}

	/**
	 * Converts the entity into the DTO returned by the API.
	 */
	private NotificationResponse mapToResponse(Notification notification) {
		NotificationResponse response = new NotificationResponse();
		response.setId(notification.getId());
		response.setType(notification.getType());
		response.setActorId(notification.getActor().getId());
		response.setActorName(notification.getActor().getName());
		response.setPostId(notification.getPostId());
		response.setMessage(notification.getMessage());
		response.setCreatedAt(notification.getCreatedAt());
		response.setReadAt(notification.getReadAt());
		return response;
	}
}
