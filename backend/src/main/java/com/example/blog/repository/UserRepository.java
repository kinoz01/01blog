package com.example.blog.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.User;

@Repository
// CRUD access for User entities plus helper lookups.
public interface UserRepository extends JpaRepository<User, UUID> {
	// Finds a user by email for login or profile lookups.
	Optional<User> findByEmail(String email);
	// Checks if an email is already taken.
	boolean existsByEmail(String email);
	// Case-insensitive name uniqueness check.
	boolean existsByNameIgnoreCase(String name);
}
