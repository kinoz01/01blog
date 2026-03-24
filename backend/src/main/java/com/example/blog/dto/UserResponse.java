package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import com.example.blog.model.Role;

import lombok.Data;

@Data
// Standard representation of a user returned to clients.
public class UserResponse {
	private UUID id;
	private String name;
	private String email;
	private Role role;
	private Instant createdAt;
	private Instant updatedAt;
}
