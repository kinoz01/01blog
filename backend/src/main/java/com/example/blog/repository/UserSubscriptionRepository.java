package com.example.blog.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.blog.model.UserSubscription;

@Repository
public interface UserSubscriptionRepository extends JpaRepository<UserSubscription, UUID> {

	boolean existsBySubscriberIdAndTargetId(UUID subscriberId, UUID targetId);

	void deleteBySubscriberIdAndTargetId(UUID subscriberId, UUID targetId);
	
	void deleteBySubscriberId(UUID subscriberId);
	
	void deleteByTargetId(UUID targetId);

	@Query("select s.subscriber.id from UserSubscription s where s.target.id = :targetId")
	List<UUID> findSubscriberIdsByTargetId(UUID targetId);

	@Query("select s.target.id from UserSubscription s where s.subscriber.id = :subscriberId")
	List<UUID> findTargetIdsBySubscriberId(UUID subscriberId);
}
