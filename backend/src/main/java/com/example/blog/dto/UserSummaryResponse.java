package com.example.blog.dto;

import java.util.UUID;

import lombok.Data;

@Data
// Minimal user info used for directories and autocomplete.
public class UserSummaryResponse {
	private UUID id;
	private String name;
}
