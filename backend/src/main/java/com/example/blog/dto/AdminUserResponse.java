package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import com.example.blog.model.Role;

import lombok.Data;

@Data
public class AdminUserResponse {
	private UUID id;
	private String name;
	private String email;
	private Role role;
	private Instant createdAt;
	private Instant updatedAt;
	private boolean banned;
	private long postCount;
}
