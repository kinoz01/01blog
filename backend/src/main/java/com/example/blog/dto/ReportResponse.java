package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import com.example.blog.model.ReportStatus;
import com.example.blog.model.ReportTargetType;

import lombok.Data;

@Data
// Response returned to admins when inspecting abuse reports.
public class ReportResponse {
	private UUID id;
	private ReportTargetType targetType;
	private ReportStatus status;
	private String reason;
	private Instant createdAt;
	private Instant resolvedAt;
	private ReporterSummary reporter;
	private ReportedUserSummary reportedUser;
	private ReportedPostSummary reportedPost;

	@Data
	// Details about the user who submitted the report.
	public static class ReporterSummary {
		private UUID id;
		private String name;
		private String email;
	}

	@Data
	// Minimal info about a reported user target.
	public static class ReportedUserSummary {
		private UUID id;
		private String name;
		private boolean banned;
		private String email;
	}

	@Data
	// Summary of a reported post and its author.
	public static class ReportedPostSummary {
		private UUID id;
		private String title;
		private boolean hidden;
		private UUID authorId;
		private String authorName;
	}
}
