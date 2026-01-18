package com.example.blog.dto;

import java.util.UUID;

import com.example.blog.model.MediaType;

import lombok.Data;

@Data
public class PostMediaResponse {
	private UUID id;
	private String url;
	private String mimeType;
	private MediaType type;
	private String originalFileName;
}
