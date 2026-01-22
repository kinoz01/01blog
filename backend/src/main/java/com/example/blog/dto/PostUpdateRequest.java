package com.example.blog.dto;

import java.util.List;
import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PostUpdateRequest {

	@NotBlank
	@Size(max = 120)
	private String title;

	@NotBlank
	@Size(max = 6000)
	private String description;

	private List<UUID> removeMediaIds;
}
