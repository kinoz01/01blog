package com.example.blog.service;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.blog.dto.AuthRequest;
import com.example.blog.dto.AuthResponse;
import com.example.blog.dto.RegisterRequest;
import com.example.blog.dto.UserResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.Role;
import com.example.blog.model.User;
import com.example.blog.repository.UserRepository;
import com.example.blog.security.JwtService;

/**
 * Handles registration, login, and profile lookups for authenticated users.
 * Wraps Spring Security primitives and emits DTOs consumed by the REST layer.
 */
@Service
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	@Autowired
	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			AuthenticationManager authenticationManager) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * Creates a brand-new user account after validating unique name/email, then
	 * returns a JWT + profile payload so the client can start an authenticated
	 * session immediately.
	 */
	public AuthResponse register(RegisterRequest request) {
		if (userRepository.existsByNameIgnoreCase(request.getName())) {
			throw new BadRequestException("Name already exists");
		}
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new BadRequestException("Email already exists");
		}
		User user = new User();
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(Role.USER);
		user.setCreatedAt(Instant.now());
		user.setUpdatedAt(Instant.now());
		User saved = userRepository.save(user);
		String token = jwtService.generateToken(saved);
		return new AuthResponse(token, jwtService.getExpiration(), mapToResponse(saved));
	}

	/**
	 * Validates the supplied credentials with the AuthenticationManager and, when
	 * successful, issues a signed JWT and profile info. Banned users receive a
	 * dedicated error message so the UI can distinguish between lockouts and bad
	 * passwords.
	 */
	public AuthResponse authenticate(AuthRequest request) {
		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
			SecurityContextHolder.getContext().setAuthentication(authentication);
			User user = (User) authentication.getPrincipal();
			String token = jwtService.generateToken(user);
			return new AuthResponse(token, jwtService.getExpiration(), mapToResponse(user));
		} catch (BadCredentialsException ex) {
			throw new UnauthorizedException("Invalid credentials");
		} catch (DisabledException ex) {
			throw new UnauthorizedException("Your account is banned. Contact support if you believe this is an error.");
		} catch (AuthenticationException ex) {
			throw new UnauthorizedException("Invalid credentials");
		}
	}

	/**
	 * Convenience helper used by `/auth/me` to turn the Spring Security principal
	 * into a serialisable `UserResponse`.
	 */
	public UserResponse getCurrentUserProfile() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !(authentication.getPrincipal() instanceof User)) {
			throw new UnauthorizedException("Authentication required");
		}
		User user = (User) authentication.getPrincipal();
		return mapToResponse(user);
	}

	/**
	 * Converts the internal `User` entity into the slimmer DTO returned to
	 * callers. Centralised here so every response is consistent.
	 */
	private UserResponse mapToResponse(User user) {
		UserResponse response = new UserResponse();
		response.setId(user.getId());
		response.setName(user.getName());
		response.setEmail(user.getEmail());
		response.setRole(user.getRole());
		response.setCreatedAt(user.getCreatedAt());
		response.setUpdatedAt(user.getUpdatedAt());
		return response;
	}
}
