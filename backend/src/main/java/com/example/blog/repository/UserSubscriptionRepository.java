package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.blog.model.UserSubscription;

@Repository
// Manages follow/subscription relationships between users.
public interface UserSubscriptionRepository extends JpaRepository<UserSubscription, UUID> {

	// Checks if a subscriber already follows the target.
	boolean existsBySubscriberIdAndTargetId(UUID subscriberId, UUID targetId);

	// Removes a single subscription edge.
	void deleteBySubscriberIdAndTargetId(UUID subscriberId, UUID targetId);
	
	// Deletes all subscriptions initiated by the user.
	void deleteBySubscriberId(UUID subscriberId);
	
	// Deletes all subscriptions pointing to the target (e.g., when deleted).
	void deleteByTargetId(UUID targetId);

	@Query("select s.subscriber.id from UserSubscription s where s.target.id = :targetId")
	// Lists IDs of users following the given target.
	List<UUID> findSubscriberIdsByTargetId(UUID targetId);

	@Query("select s.target.id from UserSubscription s where s.subscriber.id = :subscriberId")
	// Lists IDs of authors that the subscriber follows.
	List<UUID> findTargetIdsBySubscriberId(UUID subscriberId);
}
