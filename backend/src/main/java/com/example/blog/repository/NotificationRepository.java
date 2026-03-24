package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.Notification;

@Repository
// Stores Notification entities and provides recipient-centric queries.
public interface NotificationRepository extends JpaRepository<Notification, UUID> {
	// Fetches notifications for a user newest first.
	List<Notification> findByRecipientIdOrderByCreatedAtDesc(UUID recipientId);

	// Counts unread notifications for badge indicators.
	long countByRecipientIdAndReadAtIsNull(UUID recipientId);
	
	// Deletes notifications when a user account is removed.
	void deleteByRecipientId(UUID recipientId);
	
	// Deletes notifications authored by a user (e.g., on account removal).
	void deleteByActorId(UUID actorId);
}
