package com.example.blog.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.blog.dto.PostResponse;
import com.example.blog.dto.UserProfileResponse;
import com.example.blog.dto.UserRequest;
import com.example.blog.dto.UserResponse;
import com.example.blog.dto.UserUpdateRequest;
import com.example.blog.dto.UserSummaryResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.ForbiddenException;
import com.example.blog.exception.ResourceNotFoundException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.Role;
import com.example.blog.model.User;
import com.example.blog.model.UserSubscription;
import com.example.blog.repository.UserRepository;
import com.example.blog.repository.UserSubscriptionRepository;

@Service
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final PostService postService;
	private final UserSubscriptionRepository userSubscriptionRepository;

	@Autowired
	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, PostService postService,
			UserSubscriptionRepository userSubscriptionRepository) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.postService = postService;
		this.userSubscriptionRepository = userSubscriptionRepository;
	}

	public List<UserResponse> getAllUsers() {
		return userRepository.findAll().stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	public List<UserSummaryResponse> getDirectory() {
		return userRepository.findAll().stream().map(user -> {
			UserSummaryResponse summary = new UserSummaryResponse();
			summary.setId(user.getId());
			summary.setName(user.getName());
			return summary;
		}).collect(Collectors.toList());
	}

	@PostAuthorize("hasRole('ADMIN') or (returnObject != null && returnObject.email == authentication.name)")
	public UserResponse getUserById(UUID id) {
		User user = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
		return mapToResponse(user);
	}

	public UserProfileResponse getPublicProfile(UUID id, User currentUser) {
		User user = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
		List<PostResponse> posts = postService.getPostsByAuthor(id, currentUser);
		UserProfileResponse profile = new UserProfileResponse();
		profile.setId(user.getId());
		profile.setName(user.getName());
		profile.setRole(user.getRole());
		profile.setCreatedAt(user.getCreatedAt());
		profile.setUpdatedAt(user.getUpdatedAt());
		profile.setPostCount(postService.countPostsByAuthor(id));
		profile.setPosts(posts);
		boolean subscribed = currentUser != null && !currentUser.getId().equals(id)
				&& userSubscriptionRepository.existsBySubscriberIdAndTargetId(currentUser.getId(), id);
		profile.setSubscribed(subscribed);
		return profile;
	}

	@Transactional
	public void subscribe(User subscriber, UUID targetId) {
		User actor = requireAuthenticatedUser(subscriber);
		if (actor.getId().equals(targetId)) {
			throw new BadRequestException("You cannot subscribe to yourself");
		}
		User target = userRepository.findById(targetId)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + targetId));
		if (userSubscriptionRepository.existsBySubscriberIdAndTargetId(actor.getId(), targetId)) {
			return;
		}
		UserSubscription subscription = new UserSubscription();
		subscription.setSubscriber(actor);
		subscription.setTarget(target);
		userSubscriptionRepository.save(subscription);
	}

	@Transactional
	public void unsubscribe(User subscriber, UUID targetId) {
		User actor = requireAuthenticatedUser(subscriber);
		if (actor.getId().equals(targetId)) {
			return;
		}
		userSubscriptionRepository.deleteBySubscriberIdAndTargetId(actor.getId(), targetId);
	}

	public UserResponse createUser(UserRequest request) {
		if (userRepository.existsByNameIgnoreCase(request.getName())) {
			throw new BadRequestException("Name already exists");
		}
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new BadRequestException("Email already exists");
		}
		User user = new User();
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(request.getRole() == null ? Role.USER : request.getRole());
		user.setCreatedAt(Instant.now());
		user.setUpdatedAt(Instant.now());
		User saved = userRepository.save(user);
		return mapToResponse(saved);
	}

	public UserResponse updateUser(UUID id, UserUpdateRequest request, User requester) {
		if (requester == null) {
			throw new UnauthorizedException("Authentication required");
		}
		boolean isAdmin = requester.getRole() == Role.ADMIN;
		if (!isAdmin) {
			throw new ForbiddenException("Only administrators can update users");
		}
		User user = userRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));

		if (request.getName() != null && !request.getName().equals(user.getName())) {
			if (userRepository.existsByNameIgnoreCase(request.getName())) {
				throw new BadRequestException("Name already exists");
			}
			user.setName(request.getName());
		}
		if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
			if (userRepository.existsByEmail(request.getEmail())) {
				throw new BadRequestException("Email already exists");
			}
			user.setEmail(request.getEmail());
		}
		if (request.getPassword() != null) {
			user.setPassword(passwordEncoder.encode(request.getPassword()));
		}
		if (request.getRole() != null) {
			if (!isAdmin) {
				throw new ForbiddenException("Only administrators can change roles");
			}
			user.setRole(request.getRole());
		}
		user.setUpdatedAt(Instant.now());
		User updated = userRepository.save(user);
		return mapToResponse(updated);
	}

	public void deleteUser(UUID id, User requester) {
		User actor = requireAuthenticatedUser(requester);
		if (actor.getRole() != Role.ADMIN) {
			throw new ForbiddenException("Only administrators can delete users");
		}
		if (actor.getId().equals(id)) {
			throw new BadRequestException("Administrators cannot delete their own account");
		}
		if (!userRepository.existsById(id)) {
			throw new ResourceNotFoundException("User not found with id: " + id);
		}
		userRepository.deleteById(id);
	}

	private UserResponse mapToResponse(User user) {
		UserResponse response = new UserResponse();
		response.setId(user.getId());
		response.setName(user.getName());
		response.setEmail(user.getEmail());
		response.setRole(user.getRole());
		response.setCreatedAt(user.getCreatedAt());
		response.setUpdatedAt(user.getUpdatedAt());
		return response;
	}

	private User requireAuthenticatedUser(User user) {
		if (user == null) {
			throw new UnauthorizedException("Authentication required");
		}
		if (user.isBanned()) {
			throw new ForbiddenException("Your account is restricted");
		}
		return user;
	}
}
