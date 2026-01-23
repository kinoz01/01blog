package com.example.blog.dto;

import java.util.UUID;

import lombok.Data;

@Data
public class UserSummaryResponse {
	private UUID id;
	private String name;
}
