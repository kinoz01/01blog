package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.Report;
import com.example.blog.model.ReportStatus;
import com.example.blog.model.ReportTargetType;

@Repository
// Persistence interface for abuse reports and moderation queries.
public interface ReportRepository extends JpaRepository<Report, UUID> {

	// Returns all reports newest first for the admin queue.
	List<Report> findAllByOrderByCreatedAtDesc();

	// Filters reports by target type (user or post).
	List<Report> findAllByTargetTypeOrderByCreatedAtDesc(ReportTargetType targetType);

	// Finds reports filed against a user with a specific status.
	List<Report> findAllByReportedUserIdAndStatus(UUID userId, ReportStatus status);

	// Finds reports for a post with the given status.
	List<Report> findAllByReportedPostIdAndStatus(UUID postId, ReportStatus status);

	// Removes reports submitted by a user (on account deletion).
	void deleteByReporterId(UUID reporterId);

	// Deletes reports targeting a user.
	void deleteByReportedUserId(UUID userId);

	// Deletes reports for a post (e.g., before post removal).
	void deleteByReportedPostId(UUID postId);
}
