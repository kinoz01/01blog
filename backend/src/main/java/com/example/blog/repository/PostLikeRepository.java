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
public interface PostLikeRepository extends JpaRepository<PostLike, UUID> {

	boolean existsByPostIdAndUserId(UUID postId, UUID userId);

	void deleteByPostIdAndUserId(UUID postId, UUID userId);
	
	void deleteByPostId(UUID postId);
	
	void deleteByUserId(UUID userId);

	@Query("SELECT l.post.id AS postId, COUNT(l.id) AS count FROM PostLike l WHERE l.post.id IN :postIds GROUP BY l.post.id")
	List<PostMetric> aggregateCountsByPostIds(@Param("postIds") List<UUID> postIds);

	@Query("SELECT l.post.id FROM PostLike l WHERE l.user.id = :userId AND l.post.id IN :postIds")
	List<UUID> findPostIdsLikedByUser(@Param("userId") UUID userId, @Param("postIds") List<UUID> postIds);
}
