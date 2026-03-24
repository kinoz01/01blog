package com.example.blog.exception;

// Used when an entity or resource lookup returns no result.
public class ResourceNotFoundException extends RuntimeException {
	public ResourceNotFoundException(String message) {
		super(message);
	}
}
