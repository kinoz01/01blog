package com.example.blog.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.blog.dto.PostCommentRequest;
import com.example.blog.dto.ReportRequest;
import com.example.blog.dto.PostCommentResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.dto.PostUpdateRequest;
import com.example.blog.model.User;
import com.example.blog.service.ReportService;
import com.example.blog.service.PostService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/posts")
public class PostController {

	private final PostService postService;
	private final ReportService reportService;

	public PostController(PostService postService, ReportService reportService) {
		this.postService = postService;
		this.reportService = reportService;
	}

	@GetMapping
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<List<PostResponse>> getFeed(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.getFeed(currentUser));
	}

	@GetMapping("/{postId}")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> getPost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.getPost(postId, currentUser));
	}

	@PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> createPost(@RequestPart("title") String title,
			@RequestPart("description") String description,
			@RequestPart(value = "media", required = false) List<MultipartFile> media,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.createPost(title, description, media, currentUser));
	}

	@PutMapping(value = "/{postId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> updatePost(@PathVariable UUID postId,
			@Valid @RequestPart("request") PostUpdateRequest request,
			@RequestPart(value = "media", required = false) List<MultipartFile> media,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity
				.ok(postService.updatePost(postId, request.getTitle(), request.getDescription(), request.getRemoveMediaIds(), media, currentUser));
	}

	@DeleteMapping("/{postId}")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> deletePost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		postService.deletePost(postId, currentUser);
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/{postId}/likes")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> likePost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.likePost(postId, currentUser));
	}

	@DeleteMapping("/{postId}/likes")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> unlikePost(@PathVariable UUID postId, @AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.unlikePost(postId, currentUser));
	}

	@PostMapping("/{postId}/comments")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostCommentResponse> addComment(@PathVariable UUID postId,
			@Valid @RequestBody PostCommentRequest request,
			@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.addComment(postId, request.getContent(), currentUser));
	}

	@PostMapping("/{postId}/report")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> reportPost(@PathVariable UUID postId, @Valid @RequestBody ReportRequest request,
			@AuthenticationPrincipal User currentUser) {
		reportService.reportPost(postId, request, currentUser);
		return ResponseEntity.accepted().build();
	}
}
