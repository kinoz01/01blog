package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.blog.model.PostLike;
import com.example.blog.repository.projection.PostMetric;

@Repository
// Handles persistence of PostLike entities and like aggregates.
public interface PostLikeRepository extends JpaRepository<PostLike, UUID> {

	// Checks if the user has already liked the post.
	boolean existsByPostIdAndUserId(UUID postId, UUID userId);

	// Removes a single like by post/user pair.
	void deleteByPostIdAndUserId(UUID postId, UUID userId);
	
	// Bulk delete likes associated with a post.
	void deleteByPostId(UUID postId);
	
	// Deletes all likes authored by a specific user.
	void deleteByUserId(UUID userId);

	@Query("SELECT l.post.id AS postId, COUNT(l.id) AS count FROM PostLike l WHERE l.post.id IN :postIds GROUP BY l.post.id")
	// Aggregates like counts for a collection of posts.
	List<PostMetric> aggregateCountsByPostIds(@Param("postIds") List<UUID> postIds);

	@Query("SELECT l.post.id FROM PostLike l WHERE l.user.id = :userId AND l.post.id IN :postIds")
	// Returns IDs of posts from the supplied list that the user liked.
	List<UUID> findPostIdsLikedByUser(@Param("userId") UUID userId, @Param("postIds") List<UUID> postIds);
}
