package com.example.blog.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.example.blog.model.Role;

import lombok.Data;

@Data
public class UserProfileResponse {
	private UUID id;
	private String name;
	private Role role;
	private Instant createdAt;
	private Instant updatedAt;
	private long postCount;
	private List<PostResponse> posts;
	private boolean subscribed;
}
