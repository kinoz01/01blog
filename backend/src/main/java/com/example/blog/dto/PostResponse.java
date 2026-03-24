package com.example.blog.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.example.blog.model.Role;

import lombok.Data;

@Data
// Full representation of a post, including metrics and embedded media/comments.
public class PostResponse {
	private UUID id;
	private String title;
	private String description;
	private Instant createdAt;
	private Instant updatedAt;
	private AuthorSummary author;
	private List<PostMediaResponse> media;
	private long likeCount;
	private long commentCount;
	private boolean likedByCurrentUser;
	private List<PostCommentResponse> comments;
	private boolean hidden;

	@Data
	// Minimal author info bundled with each post response.
	public static class AuthorSummary {
		private UUID id;
		private String name;
		private Role role;
	}
}
