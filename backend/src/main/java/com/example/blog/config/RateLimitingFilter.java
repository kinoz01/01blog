package com.example.blog.config;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.blog.dto.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Servlet filter that enforces a per-IP token bucket so abusive clients receive
 * HTTP 429 responses instead of overwhelming the API.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

	private static final int CAPACITY = 100;
	private static final long REFILL_WINDOW_MS = 1_000;

	private final Map<String, SimpleBucket> cache = new ConcurrentHashMap<>();
	@Autowired
    private ObjectMapper objectMapper;

	/**
	 * Entry point for each HTTP request. We grab the caller's IP address, fetch a
	 * token bucket for that IP (creating one if needed), and only allow the request
	 * to proceed down the filter chain when a token is available. Otherwise, we send
	 * back a 429 response with a JSON payload describing the error.
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain nextFilter)
			throws ServletException, IOException {
		String ip = request.getRemoteAddr();
		SimpleBucket bucket = cache.computeIfAbsent(ip, this::createBucket);
		if (bucket.tryConsume(1)) {
			nextFilter.doFilter(request, response); // Calls the next filter in the chain or the target resource
		} else {
			response.setHeader("X-RateLimit-Limit", String.valueOf(CAPACITY));
			response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
			response.setContentType("application/json");
			ApiError error = new ApiError(HttpStatus.TOO_MANY_REQUESTS.value(), "Too Many Requests",
					"Rate limit exceeded. Please try again shortly.", request.getRequestURI());
			response.getWriter().write(objectMapper.writeValueAsString(error));
		}
	}

	/**
	 * Builds a new bucket with the global capacity/refill settings. Called lazily
	 * whenever we see a new IP address.
	 */
	private SimpleBucket createBucket(String key) {
		return new SimpleBucket(CAPACITY, REFILL_WINDOW_MS);
	}

	/**
	 * Skip rate limiting for CORS preflight calls so browsers can negotiate
	 * headers without being throttled.
	 */
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return "OPTIONS".equalsIgnoreCase(request.getMethod());
	}

	/**
	 * Very small, thread-safe token bucket implementation used per client IP.
	 */
	private static final class SimpleBucket {
		private final int capacity;
		private final long refillWindowMs;
		private double tokens;
		private long lastRefill;

		/**
		 * Buckets start full so the first burst of requests is accepted immediately.
		 */
		private SimpleBucket(int capacity, long refillWindowMs) {
			this.capacity = capacity;
			this.refillWindowMs = refillWindowMs;
			this.tokens = capacity;
			this.lastRefill = System.currentTimeMillis();
		}

		/**
		 * Refill tokens based on elapsed time and, if enough are available, consume
		 * the requested amount atomically.
		 */
		private synchronized boolean tryConsume(int amount) {
			refill();
			if (tokens >= amount) {
				tokens -= amount;
				return true;
			}
			return false;
		}

		/**
		 * Computes how many tokens should be added since the last refill tick and
		 * caps the bucket at its configured capacity.
		 */
		private void refill() {
			long now = System.currentTimeMillis();
			long elapsed = now - lastRefill;
			if (elapsed <= 0) {
				return;
			}
			double tokensToAdd = (elapsed / (double) refillWindowMs) * capacity;
			if (tokensToAdd > 0) {
				tokens = Math.min(capacity, tokens + tokensToAdd);
				lastRefill = now;
			}
		}
	}
}
