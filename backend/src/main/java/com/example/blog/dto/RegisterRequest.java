package com.example.blog.dto;

import com.example.blog.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

	@NotBlank
	@Size(min = 4, max = 25)
	private String name;

	@NotBlank
	@Email
	private String email;

	@NotBlank
	@Size(min = 8, message = "Password should at least be 8 characters")
	private String password;

	private Role role = Role.USER;
}
