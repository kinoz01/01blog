package com.example.blog.exception;

// Raised when file upload or deletion operations fail.
public class MediaStorageException extends RuntimeException {

	public MediaStorageException(String message) {
		super(message);
	}

	public MediaStorageException(String message, Throwable cause) {
		super(message, cause);
	}
}
