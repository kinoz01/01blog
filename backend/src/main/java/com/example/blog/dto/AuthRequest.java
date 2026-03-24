package com.example.blog.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
// Login credentials payload.
public class AuthRequest {
	@NotBlank
	@Email
	private String email;

	@NotBlank
	private String password;
}
