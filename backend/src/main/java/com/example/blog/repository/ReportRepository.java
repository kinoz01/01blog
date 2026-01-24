package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.Report;
import com.example.blog.model.ReportStatus;
import com.example.blog.model.ReportTargetType;

@Repository
public interface ReportRepository extends JpaRepository<Report, UUID> {

	List<Report> findAllByOrderByCreatedAtDesc();

	List<Report> findAllByTargetTypeOrderByCreatedAtDesc(ReportTargetType targetType);

	List<Report> findAllByReportedUserIdAndStatus(UUID userId, ReportStatus status);

	List<Report> findAllByReportedPostIdAndStatus(UUID postId, ReportStatus status);
}
