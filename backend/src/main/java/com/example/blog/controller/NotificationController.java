package com.example.blog.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.blog.dto.NotificationResponse;
import com.example.blog.model.User;
import com.example.blog.service.NotificationService;

/**
 * Authenticated endpoints for listing, deleting, and otherwise managing user
 * notifications.
 */
@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

	private final NotificationService notificationService;

	public NotificationController(NotificationService notificationService) {
		this.notificationService = notificationService;
	}

	@GetMapping
	@PreAuthorize("isAuthenticated()")
	// Returns the recipient's notifications sorted by recency.
	public ResponseEntity<List<NotificationResponse>> getNotifications(@AuthenticationPrincipal @NonNull User user) {
		return ResponseEntity.ok(notificationService.getNotifications(user));
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("isAuthenticated()")
	// Deletes a notification after verifying it belongs to the caller.
	public ResponseEntity<Void> deleteNotification(@PathVariable @NonNull UUID id,
			@AuthenticationPrincipal @NonNull User user) {
		notificationService.delete(user, id);
		return ResponseEntity.noContent().build();
	}
}
