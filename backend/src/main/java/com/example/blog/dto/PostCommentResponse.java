package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import lombok.Data;

@Data
public class PostCommentResponse {
	private UUID id;
	private String content;
	private Instant createdAt;
	private Instant updatedAt;
	private AuthorSummary author;

	@Data
	public static class AuthorSummary {
		private UUID id;
		private String name;
	}
}
