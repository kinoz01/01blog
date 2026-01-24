package com.example.blog.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.blog.dto.AdminUserResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.dto.ReportResponse;
import com.example.blog.model.User;
import com.example.blog.service.AdminService;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

	private final AdminService adminService;

	public AdminController(AdminService adminService) {
		this.adminService = adminService;
	}

	@GetMapping("/reports")
	public ResponseEntity<List<ReportResponse>> getReports(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.getReports(currentUser));
	}
	
	@GetMapping("/users")
	public ResponseEntity<List<AdminUserResponse>> getUsers(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.getUsers(currentUser));
	}

	@GetMapping("/posts")
	public ResponseEntity<List<PostResponse>> getPosts(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.getAllPosts(currentUser));
	}

	@PostMapping("/reports/{reportId}/resolve")
	public ResponseEntity<ReportResponse> resolveReport(@PathVariable UUID reportId,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.resolveReport(reportId, currentUser));
	}

	@PostMapping("/users/{userId}/ban")
	public ResponseEntity<Void> banUser(@PathVariable UUID userId, @AuthenticationPrincipal User currentUser) {
		adminService.banUser(userId, currentUser);
		return ResponseEntity.accepted().build();
	}

	@DeleteMapping("/users/{userId}/ban")
	public ResponseEntity<Void> unbanUser(@PathVariable UUID userId, @AuthenticationPrincipal User currentUser) {
		adminService.unbanUser(userId, currentUser);
		return ResponseEntity.noContent().build();
	}

	@DeleteMapping("/users/{userId}")
	public ResponseEntity<Void> removeUser(@PathVariable UUID userId, @AuthenticationPrincipal User currentUser) {
		adminService.removeUser(userId, currentUser);
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/posts/{postId}/hide")
	public ResponseEntity<PostResponse> hidePost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.hidePost(postId, currentUser));
	}

	@DeleteMapping("/posts/{postId}/hide")
	public ResponseEntity<PostResponse> unhidePost(@PathVariable UUID postId,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(adminService.unhidePost(postId, currentUser));
	}

	@DeleteMapping("/posts/{postId}")
	public ResponseEntity<Void> deletePost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		adminService.deletePost(postId, currentUser);
		return ResponseEntity.noContent().build();
	}
}
