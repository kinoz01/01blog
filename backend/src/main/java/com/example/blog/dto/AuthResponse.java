package com.example.blog.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthResponse {
	private String token;
	private String tokenType = "Bearer";
	private long expiresIn;
	@JsonInclude(JsonInclude.Include.NON_NULL)
	private UserResponse user;

	public AuthResponse(String token, long expiresIn) {
		this.token = token;
		this.expiresIn = expiresIn;
	}

	public AuthResponse(String token, long expiresIn, UserResponse user) {
		this.token = token;
		this.expiresIn = expiresIn;
		this.user = user;
	}
}
