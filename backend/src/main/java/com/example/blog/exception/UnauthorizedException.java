package com.example.blog.exception;

// Signals that authentication is missing or invalid.
public class UnauthorizedException extends RuntimeException {
	public UnauthorizedException(String message) {
		super(message);
	}
}
