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
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.blog.dto.ReportRequest;
import com.example.blog.dto.UserProfileResponse;
import com.example.blog.dto.UserRequest;
import com.example.blog.dto.UserResponse;
import com.example.blog.dto.UserSummaryResponse;
import com.example.blog.dto.UserUpdateRequest;
import com.example.blog.model.User;
import com.example.blog.service.ReportService;
import com.example.blog.service.UserService;

import jakarta.validation.Valid;

/**
 * User-focused endpoints covering directory lookups, subscriptions, admin user
 * management, and abuse reports.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;
	private final ReportService reportService;

	public UserController(UserService userService, ReportService reportService) {
		this.userService = userService;
		this.reportService = reportService;
	}

	@GetMapping
	@PreAuthorize("hasRole('ADMIN')")
	// Lists all users for admin dashboards.
	public ResponseEntity<List<UserResponse>> getUsers() {
		return ResponseEntity.ok(userService.getAllUsers());
	}

	@GetMapping("/directory")
	@PreAuthorize("isAuthenticated()")
	// Returns a lightweight users directory list for autocomplete or browsing or search.
	public ResponseEntity<List<UserSummaryResponse>> getDirectory() {
		return ResponseEntity.ok(userService.getDirectory());
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or (isAuthenticated() and #id == principal.id)")
	// Fetches a specific user, restricted to admins or the user themselves.
	public ResponseEntity<UserResponse> getUserById(@PathVariable @NonNull UUID id) {
		return ResponseEntity.ok(userService.getUserById(id));
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN')")
	// Allows admins to manually create a user account.
	public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserRequest request) {
		return ResponseEntity.ok(userService.createUser(request));
	}

	@GetMapping("/{id}/profile")
	@PreAuthorize("isAuthenticated()")
	// Builds a public-facing profile for the specified user.
	public ResponseEntity<UserProfileResponse> getPublicProfile(@PathVariable @NonNull UUID id,
			@AuthenticationPrincipal @NonNull User currentUser) {
		return ResponseEntity.ok(userService.getPublicProfile(id, currentUser));
	}

	@PostMapping("/{id}/subscribe")
	@PreAuthorize("isAuthenticated()")
	// Subscribes the current user to another author.
	public ResponseEntity<Void> subscribe(@PathVariable @NonNull UUID id,
			@AuthenticationPrincipal @NonNull User currentUser) {
		userService.subscribe(currentUser, id);
		return ResponseEntity.ok().build();
	}

	@DeleteMapping("/{id}/subscribe")
	@PreAuthorize("isAuthenticated()")
	// Removes a subscription relationship when requested.
	public ResponseEntity<Void> unsubscribe(@PathVariable @NonNull UUID id,
			@AuthenticationPrincipal @NonNull User currentUser) {
		userService.unsubscribe(currentUser, id);
		return ResponseEntity.noContent().build();
	}

	@PutMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	// Performs a full update on a user record (admin-only).
	public ResponseEntity<UserResponse> updateUser(@PathVariable @NonNull UUID id,
			@Valid @RequestBody UserUpdateRequest request, @AuthenticationPrincipal @NonNull User currentUser) {
		return ResponseEntity.ok(userService.updateUser(id, request, currentUser));
	}

	@PatchMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	// Applies a partial update for cases where not all fields change.
	public ResponseEntity<UserResponse> partiallyUpdateUser(@PathVariable @NonNull UUID id,
			@RequestBody UserUpdateRequest request, @AuthenticationPrincipal @NonNull User currentUser) {
		return ResponseEntity.ok(userService.updateUser(id, request, currentUser));
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	// Removes a user after the admin confirms the action.
	public ResponseEntity<Void> deleteUser(@PathVariable @NonNull UUID id,
			@AuthenticationPrincipal @NonNull User currentUser) {
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/{id}/report")
	@PreAuthorize("isAuthenticated()")
	// Files an abuse report targeting the specified user.
	public ResponseEntity<Void> reportUser(@PathVariable @NonNull UUID id, @Valid @RequestBody ReportRequest request,
			@AuthenticationPrincipal @NonNull User currentUser) {
		reportService.reportUser(id, request, currentUser);
		return ResponseEntity.accepted().build();
	}
}
