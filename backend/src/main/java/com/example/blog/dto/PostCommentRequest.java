package com.example.blog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
// Request body for adding a comment to a post.
public class PostCommentRequest {

	@NotBlank
	@Size(min = 1, max = 1000)
	private String content;
}
