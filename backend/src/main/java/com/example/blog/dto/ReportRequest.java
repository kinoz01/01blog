package com.example.blog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ReportRequest {

	@NotBlank
	@Size(min = 5, max = 1000)
	private String reason;
}
