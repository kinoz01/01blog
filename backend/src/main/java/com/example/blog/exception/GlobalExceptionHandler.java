package com.example.blog.exception;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import com.example.blog.dto.ApiError;

import jakarta.validation.ConstraintViolationException;

/**
 * Centralized REST exception handler that converts application exceptions into
 * {@link ApiError} responses.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(ResourceNotFoundException.class)
	// Returns 404 when entities cannot be located.
	public ResponseEntity<ApiError> handleNotFound(ResourceNotFoundException ex, WebRequest request) {
		return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage(), request);
	}

	@ExceptionHandler({ BadRequestException.class, ConstraintViolationException.class })
	// Handles validation and business rule failures with 400 responses.
	public ResponseEntity<ApiError> handleBadRequest(Exception ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
	}

	@ExceptionHandler(UnauthorizedException.class)
	// Maps unauthorized errors to HTTP 401.
	public ResponseEntity<ApiError> handleUnauthorized(UnauthorizedException ex, WebRequest request) {
		return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
	}

	@ExceptionHandler(ForbiddenException.class)
	// Returns 403 when authenticated users lack privileges.
	public ResponseEntity<ApiError> handleForbidden(ForbiddenException ex, WebRequest request) {
		return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage(), request);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	// Aggregates field validation errors into a single 400 message.
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
		StringBuilder builder = new StringBuilder();
		for (FieldError error : ex.getBindingResult().getFieldErrors()) {
			builder.append(error.getField()).append(" ").append(error.getDefaultMessage()).append("; ");
		}
		return buildResponse(HttpStatus.BAD_REQUEST, builder.toString().trim(), request);
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	// Communicates supported methods when a wrong HTTP verb is used.
	public ResponseEntity<ApiError> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex,
			WebRequest request) {
		Set<HttpMethod> supportedMethods = ex.getSupportedHttpMethods();
		String supported = supportedMethods == null ? "none"
				: supportedMethods.stream().map(HttpMethod::name).collect(Collectors.joining(", "));
		String message = String.format("Request method '%s' is not supported. Supported methods: %s", ex.getMethod(),
				supported);
		return buildResponse(HttpStatus.METHOD_NOT_ALLOWED, message, request);
	}

	@ExceptionHandler(NoHandlerFoundException.class)
	// Sends 404 when no controller mapping matches the request.
	public ResponseEntity<ApiError> handleNoHandler(NoHandlerFoundException ex, WebRequest request) {
		String message = String.format("No handler found for %s %s", ex.getHttpMethod(), ex.getRequestURL());
		return buildResponse(HttpStatus.NOT_FOUND, message, request);
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	// Indicates malformed or missing request bodies.
	public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Request body is missing or malformed", request);
	}

	@ExceptionHandler(AccessDeniedException.class)
	// Covers Spring Security access control denials.
	public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
		String message = ex.getMessage() == null ? "Access denied" : ex.getMessage();
		return buildResponse(HttpStatus.FORBIDDEN, message, request);
	}

	@ExceptionHandler(AuthenticationException.class)
	// Handles generic authentication problems.
	public ResponseEntity<ApiError> handleAuthentication(AuthenticationException ex, WebRequest request) {
		return buildResponse(HttpStatus.UNAUTHORIZED, "Authentication required", request);
	}

	@ExceptionHandler(MediaStorageException.class)
	// Surfaces upload/storage problems as 400 errors.
	public ResponseEntity<ApiError> handleMediaStorage(MediaStorageException ex, WebRequest request) {
		String message = ex.getMessage() == null ? "Unable to store media" : ex.getMessage();
		return buildResponse(HttpStatus.BAD_REQUEST, message, request);
	}

	@ExceptionHandler(Exception.class)
	// Fallback for unexpected exceptions.
	public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
		return buildResponse(HttpStatus.BAD_REQUEST, "Unsupported request.", request);
	}

	private ResponseEntity<ApiError> buildResponse(HttpStatus status, String message, WebRequest request) {
		ApiError error = new ApiError(status.value(), status.getReasonPhrase(), message,
				request.getDescription(false).replace("uri=", ""));
		return new ResponseEntity<>(error, status);
	}
}
