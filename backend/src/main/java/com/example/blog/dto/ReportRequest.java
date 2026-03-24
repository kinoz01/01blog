package com.example.blog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
// Body used when filing a report against a user or post.
public class ReportRequest {

	@NotBlank
	@Size(min = 5, max = 1000)
	private String reason;
}
