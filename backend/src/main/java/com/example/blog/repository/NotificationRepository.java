package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.blog.model.Notification;

@Repository
public interface NotificationRepository extends JpaRepository<Notification, UUID> {
	List<Notification> findByRecipientIdOrderByCreatedAtDesc(UUID recipientId);

	long countByRecipientIdAndReadAtIsNull(UUID recipientId);
	
	void deleteByRecipientId(UUID recipientId);
	
	void deleteByActorId(UUID actorId);
}
