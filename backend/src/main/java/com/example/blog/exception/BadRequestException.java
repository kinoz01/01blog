package com.example.blog.exception;

// Thrown when client input fails validation or business rules.
public class BadRequestException extends RuntimeException {
	public BadRequestException(String message) {
		super(message);
	}
}
