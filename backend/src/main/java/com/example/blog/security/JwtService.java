package com.example.blog.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
// Encapsulates JWT creation and parsing logic for the API.
public class JwtService {

	private final String secret;
	private final long expiration;

	// Builds the service with injected secret/expiration properties.
	public JwtService(
			@Value("${app.jwt.secret:bGV0cy1wbGF5LXNlY3VyZS1zZWNyZXQtbGV0cy1wbGF5LXNlY3VyZS1zZWNyZXQ=}") String secret,
			@Value("${app.jwt.expiration:3600000}") long expiration) {
		this.secret = secret;
		this.expiration = expiration;
	}

	// Extracts the username (subject) from a JWT.
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject); 
	}

	// Generic helper that maps JWT claims to a desired value.
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	// Exposes configured expiration milliseconds for clients.
	public long getExpiration() {
		return expiration;
	}

	// Generates a signed JWT for the provided user without extra claims.
	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}

	// Generates a signed JWT embedding the provided claims.
	public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
	}

	// Checks whether the token is past its expiration time.
	public boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	// Pulls the expiration timestamp from the token.
	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	// Parses the JWS and returns all claims.
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
	}

	// Builds the HMAC signing key from the configured secret.
	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secret);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
