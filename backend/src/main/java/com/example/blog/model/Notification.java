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
@Table(name = "notifications")
@Getter
@Setter
public class Notification {

	public enum Type {
		POST_PUBLISHED
	}

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "recipient_id")
	private User recipient;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "actor_id")
	private User actor;

	@Column(name = "post_id", nullable = false)
	private UUID postId;

	@Column(nullable = false, length = 200)
	private String message;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 40)
	private Type type = Type.POST_PUBLISHED;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "read_at")
	private Instant readAt;

	@PrePersist
	public void onCreate() {
		createdAt = Instant.now();
	}

	public boolean isRead() {
		return readAt != null;
	}
}
