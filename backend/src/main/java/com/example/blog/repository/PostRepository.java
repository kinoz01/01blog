package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.Post;

@Repository
// Primary persistence interface for Post entities plus feed helpers.
public interface PostRepository extends JpaRepository<Post, UUID> {
	// Returns every post newest first.
	List<Post> findAllByOrderByCreatedAtDesc();
	// Fetches all posts for a single author ordered by recency.
	List<Post> findAllByAuthorIdOrderByCreatedAtDesc(UUID authorId);
	// Retrieves posts for multiple authors (used for feeds).
	List<Post> findAllByAuthorIdInOrderByCreatedAtDesc(Iterable<UUID> authorIds);
	// Counts how many posts an author has published.
	long countByAuthorId(UUID authorId);
}
