package com.example.blog.exception;

// Indicates the caller is authenticated but lacks permissions.
public class ForbiddenException extends RuntimeException {
	public ForbiddenException(String message) {
		super(message);
	}
}
