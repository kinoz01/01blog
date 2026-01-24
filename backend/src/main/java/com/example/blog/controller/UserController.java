package com.example.blog.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
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
	public ResponseEntity<List<UserResponse>> getUsers() {
		return ResponseEntity.ok(userService.getAllUsers());
	}

	@GetMapping("/directory")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<List<UserSummaryResponse>> getDirectory() {
		return ResponseEntity.ok(userService.getDirectory());
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or (isAuthenticated() and #id == principal.id)")
	public ResponseEntity<UserResponse> getUserById(@PathVariable UUID id) {
		return ResponseEntity.ok(userService.getUserById(id));
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserRequest request) {
		return ResponseEntity.ok(userService.createUser(request));
	}

	@GetMapping("/{id}/profile")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<UserProfileResponse> getPublicProfile(@PathVariable UUID id,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(userService.getPublicProfile(id, currentUser));
	}

	@PostMapping("/{id}/subscribe")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> subscribe(@PathVariable UUID id, @AuthenticationPrincipal User currentUser) {
		userService.subscribe(currentUser, id);
		return ResponseEntity.ok().build();
	}

	@DeleteMapping("/{id}/subscribe")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> unsubscribe(@PathVariable UUID id, @AuthenticationPrincipal User currentUser) {
		userService.unsubscribe(currentUser, id);
		return ResponseEntity.noContent().build();
	}

	@PutMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<UserResponse> updateUser(@PathVariable UUID id, @Valid @RequestBody UserUpdateRequest request,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(userService.updateUser(id, request, currentUser));
	}

	@PatchMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<UserResponse> partiallyUpdateUser(@PathVariable UUID id,
			@RequestBody UserUpdateRequest request, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(userService.updateUser(id, request, currentUser));
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Void> deleteUser(@PathVariable UUID id) {
		userService.deleteUser(id);
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/{id}/report")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> reportUser(@PathVariable UUID id, @Valid @RequestBody ReportRequest request,
			@AuthenticationPrincipal User currentUser) {
		reportService.reportUser(id, request, currentUser);
		return ResponseEntity.accepted().build();
	}
}
