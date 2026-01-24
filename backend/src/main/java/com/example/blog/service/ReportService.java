package com.example.blog.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.example.blog.dto.ReportRequest;
import com.example.blog.dto.ReportResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.Post;
import com.example.blog.model.Report;
import com.example.blog.model.ReportStatus;
import com.example.blog.model.ReportTargetType;
import com.example.blog.model.Role;
import com.example.blog.model.User;
import com.example.blog.repository.PostRepository;
import com.example.blog.repository.ReportRepository;
import com.example.blog.repository.UserRepository;

@Service
public class ReportService {

	private final ReportRepository reportRepository;
	private final UserRepository userRepository;
	private final PostRepository postRepository;

	public ReportService(ReportRepository reportRepository, UserRepository userRepository, PostRepository postRepository) {
		this.reportRepository = reportRepository;
		this.userRepository = userRepository;
		this.postRepository = postRepository;
	}

	@Transactional
	public void reportUser(UUID userId, ReportRequest request, User reporter) {
		User actor = requireActiveUser(reporter);
		User target = userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User not found"));
		if (target.getId().equals(actor.getId())) {
			throw new BadRequestException("You cannot report yourself");
		}
		String reason = normalizeReason(request.getReason());
		Report report = new Report();
		report.setTargetType(ReportTargetType.USER);
		report.setReporter(actor);
		report.setReportedUser(target);
		report.setReason(reason);
		reportRepository.save(report);
	}

	@Transactional
	public void reportPost(UUID postId, ReportRequest request, User reporter) {
		User actor = requireActiveUser(reporter);
		Post post = postRepository.findById(postId)
				.orElseThrow(() -> new ResourceNotFoundException("Post not found"));
		if (post.getAuthor().getId().equals(actor.getId())) {
			throw new BadRequestException("You cannot report your own content");
		}
		String reason = normalizeReason(request.getReason());
		Report report = new Report();
		report.setTargetType(ReportTargetType.POST);
		report.setReporter(actor);
		report.setReportedPost(post);
		report.setReason(reason);
		reportRepository.save(report);
	}

	@Transactional(readOnly = true)
	public List<ReportResponse> getAllReports(User admin) {
		ensureAdmin(admin);
		return reportRepository.findAllByOrderByCreatedAtDesc().stream()
				.map(this::mapToResponse)
				.collect(Collectors.toList());
	}

	@Transactional
	public ReportResponse resolveReport(UUID reportId, User admin) {
		ensureAdmin(admin);
		Report report = reportRepository.findById(reportId)
				.orElseThrow(() -> new ResourceNotFoundException("Report not found"));
		if (!report.isResolved()) {
			report.setStatus(ReportStatus.RESOLVED);
			report.setResolvedAt(Instant.now());
			report = reportRepository.save(report);
		}
		return mapToResponse(report);
	}

	@Transactional
	public void resolveReportsForUser(UUID userId) {
		List<Report> reports = reportRepository.findAllByReportedUserIdAndStatus(userId, ReportStatus.OPEN);
		for (Report report : reports) {
			report.setStatus(ReportStatus.RESOLVED);
			report.setResolvedAt(Instant.now());
		}
		reportRepository.saveAll(reports);
	}

	@Transactional
	public void resolveReportsForPost(UUID postId) {
		List<Report> reports = reportRepository.findAllByReportedPostIdAndStatus(postId, ReportStatus.OPEN);
		for (Report report : reports) {
			report.setStatus(ReportStatus.RESOLVED);
			report.setResolvedAt(Instant.now());
		}
		reportRepository.saveAll(reports);
	}

	private User requireActiveUser(User user) {
		if (user == null) {
			throw new UnauthorizedException("Authentication required");
		}
		if (user.isBanned()) {
			throw new ForbiddenException("You are not allowed to perform this action");
		}
		return user;
	}

	private void ensureAdmin(User user) {
		if (user == null || user.getRole() != Role.ADMIN) {
			throw new ForbiddenException("Administrator privileges required");
		}
	}

	private String normalizeReason(String rawReason) {
		if (!StringUtils.hasText(rawReason)) {
			throw new BadRequestException("Reason is required");
		}
		String reason = rawReason.trim();
		if (reason.length() > 1000) {
			reason = reason.substring(0, 1000);
		}
		return reason;
	}

	private ReportResponse mapToResponse(Report report) {
		ReportResponse response = new ReportResponse();
		response.setId(report.getId());
		response.setTargetType(report.getTargetType());
		response.setStatus(report.getStatus());
		response.setReason(report.getReason());
		response.setCreatedAt(report.getCreatedAt());
		response.setResolvedAt(report.getResolvedAt());

		ReportResponse.ReporterSummary reporter = new ReportResponse.ReporterSummary();
		reporter.setId(report.getReporter().getId());
		reporter.setName(report.getReporter().getName());
		reporter.setEmail(report.getReporter().getEmail());
		response.setReporter(reporter);

		if (report.getReportedUser() != null) {
			ReportResponse.ReportedUserSummary target = new ReportResponse.ReportedUserSummary();
			target.setId(report.getReportedUser().getId());
			target.setName(report.getReportedUser().getName());
			target.setEmail(report.getReportedUser().getEmail());
			target.setBanned(report.getReportedUser().isBanned());
			response.setReportedUser(target);
		}

		if (report.getReportedPost() != null) {
			ReportResponse.ReportedPostSummary postSummary = new ReportResponse.ReportedPostSummary();
			postSummary.setId(report.getReportedPost().getId());
			postSummary.setTitle(report.getReportedPost().getTitle());
			postSummary.setHidden(report.getReportedPost().isHidden());
			if (report.getReportedPost().getAuthor() != null) {
				postSummary.setAuthorId(report.getReportedPost().getAuthor().getId());
				postSummary.setAuthorName(report.getReportedPost().getAuthor().getName());
			}
			response.setReportedPost(postSummary);
		}

		return response;
	}
}
