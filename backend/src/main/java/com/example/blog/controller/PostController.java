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

import com.example.blog.dto.PostResponse;
import com.example.blog.dto.PostUpdateRequest;
import com.example.blog.model.User;
import com.example.blog.service.PostService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/posts")
public class PostController {

	private final PostService postService;

	public PostController(PostService postService) {
		this.postService = postService;
	}

	@GetMapping
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<List<PostResponse>> getFeed(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(postService.getFeed(currentUser));
	}

	@GetMapping("/{postId}")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<PostResponse> getPost(@PathVariable UUID postId) {
		return ResponseEntity.ok(postService.getPost(postId));
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
}
