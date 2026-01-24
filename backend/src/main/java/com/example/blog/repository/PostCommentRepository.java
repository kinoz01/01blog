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
public interface PostCommentRepository extends JpaRepository<PostComment, UUID> {

	List<PostComment> findAllByPostIdOrderByCreatedAtAsc(UUID postId);

	List<PostComment> findAllByPostIdInOrderByCreatedAtAsc(List<UUID> postIds);

	@Query("SELECT c.post.id AS postId, COUNT(c.id) AS count FROM PostComment c WHERE c.post.id IN :postIds GROUP BY c.post.id")
	List<PostMetric> aggregateCountsByPostIds(@Param("postIds") List<UUID> postIds);

	long countByPostId(UUID postId);
	
	void deleteByPostId(UUID postId);
	
	void deleteByAuthorId(UUID authorId);
}
