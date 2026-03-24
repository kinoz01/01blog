package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.blog.model.PostComment;
import com.example.blog.repository.projection.PostMetric;

@Repository
// Repository for PostComment entities and per-post comment metrics.
public interface PostCommentRepository extends JpaRepository<PostComment, UUID> {

	// Loads all comments for a post ordered oldest-first.
	List<PostComment> findAllByPostIdOrderByCreatedAtAsc(UUID postId);

	// Fetches comments for multiple posts (used when embedding threads).
	List<PostComment> findAllByPostIdInOrderByCreatedAtAsc(List<UUID> postIds);

	@Query("SELECT c.post.id AS postId, COUNT(c.id) AS count FROM PostComment c WHERE c.post.id IN :postIds GROUP BY c.post.id")
	// Aggregates comment counts for a set of post IDs.
	List<PostMetric> aggregateCountsByPostIds(@Param("postIds") List<UUID> postIds);

	// Counts comments tied to a single post.
	long countByPostId(UUID postId);
	
	// Deletes comments when a post is removed.
	void deleteByPostId(UUID postId);
	
	// Deletes comments authored by a given user.
	void deleteByAuthorId(UUID authorId);
}
