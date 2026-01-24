package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import com.example.blog.model.ReportStatus;
import com.example.blog.model.ReportTargetType;

import lombok.Data;

@Data
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
	public static class ReporterSummary {
		private UUID id;
		private String name;
		private String email;
	}

	@Data
	public static class ReportedUserSummary {
		private UUID id;
		private String name;
		private boolean banned;
		private String email;
	}

	@Data
	public static class ReportedPostSummary {
		private UUID id;
		private String title;
		private boolean hidden;
		private UUID authorId;
		private String authorName;
	}
}
