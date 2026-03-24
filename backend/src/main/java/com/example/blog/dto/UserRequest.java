package com.example.blog.dto;

import com.example.blog.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
// Admin payload for creating a user through the management APIs.
public class UserRequest {

	@NotBlank
	@Size(min = 2, max = 50)
	private String name;

	@NotBlank
	@Email
	private String email;

	@NotBlank
	@Size(min = 8)
	private String password;

	@NotNull
	private Role role;
}
