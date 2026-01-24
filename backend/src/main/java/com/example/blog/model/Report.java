package com.example.blog.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "reports")
@Getter
@Setter
public class Report {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	@Enumerated(EnumType.STRING)
	@Column(name = "target_type", nullable = false, length = 20)
	private ReportTargetType targetType;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private ReportStatus status = ReportStatus.OPEN;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "reporter_id", nullable = false)
	private User reporter;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "reported_user_id")
	private User reportedUser;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "reported_post_id")
	private Post reportedPost;

	@Column(nullable = false, length = 1000)
	private String reason;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "resolved_at")
	private Instant resolvedAt;

	@PrePersist
	public void onCreate() {
		createdAt = Instant.now();
	}

	public boolean isResolved() {
		return status == ReportStatus.RESOLVED;
	}
}
