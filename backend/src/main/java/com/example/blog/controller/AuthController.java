package com.example.blog.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.blog.dto.AuthRequest;
import com.example.blog.dto.AuthResponse;
import com.example.blog.dto.RegisterRequest;
import com.example.blog.dto.UserResponse;
import com.example.blog.service.AuthService;

import jakarta.annotation.security.PermitAll;
import jakarta.validation.Valid;

/**
 * Handles registration, login, and the authenticated user's profile lookup.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;

	public AuthController(AuthService authService) { // Constructor injection
		this.authService = authService;
	}

	@PostMapping("/register")
	@PermitAll
	// Creates a new account and returns the JWT/session payload.
	public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
		return ResponseEntity.ok(authService.register(request));
	}

	@PostMapping("/login")
	@PermitAll
	// Authenticates credentials and responds with a JWT.
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
		return ResponseEntity.ok(authService.authenticate(request));
	}

	@GetMapping("/me")
	@PreAuthorize("isAuthenticated()")
	// Returns the profile for the currently authenticated principal.
	public ResponseEntity<UserResponse> me() {
		return ResponseEntity.ok(authService.getCurrentUserProfile());
	}
}
