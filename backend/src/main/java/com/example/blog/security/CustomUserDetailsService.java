package com.example.blog.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.blog.repository.UserRepository;

@Service
// Bridges Spring Security's UserDetailsService to our UserRepository.
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	// Constructor injection for the backing repository.
	public CustomUserDetailsService(UserRepository userRepository) { // Injection point
		this.userRepository = userRepository;
	}

	@Override
	// Loads a user by email (username) or throws when missing.
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
	}
}
