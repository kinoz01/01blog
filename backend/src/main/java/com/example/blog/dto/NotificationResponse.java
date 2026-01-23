package com.example.blog.dto;

import java.time.Instant;
import java.util.UUID;

import com.example.blog.model.Notification.Type;

import lombok.Data;

@Data
public class NotificationResponse {
	private UUID id;
	private Type type;
	private UUID actorId;
	private String actorName;
	private UUID postId;
	private String message;
	private Instant createdAt;
	private Instant readAt;
}
