package com.example.blog.dto;

import com.example.blog.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserUpdateRequest {

	@Size(min = 2, max = 50)
	private String name;

	@Email
	private String email;

	@Size(min = 8)
	private String password;

	private Role role;
}
