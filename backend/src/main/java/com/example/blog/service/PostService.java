package com.example.blog.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.example.blog.dto.PostMediaResponse;
import com.example.blog.dto.PostResponse;
import com.example.blog.exception.BadRequestException;
import com.example.blog.exception.UnauthorizedException;
import com.example.blog.model.MediaType;
import com.example.blog.model.Post;
import com.example.blog.model.PostMedia;
import com.example.blog.model.User;
import com.example.blog.repository.PostRepository;
import com.example.blog.service.MediaStorageService.StoredMedia;

@Service
public class PostService {

	private static final int MAX_MEDIA = 10;
	private static final int MAX_TITLE_LENGTH = 120;
	private static final int MAX_POST_LENGTH = 6000;

	private final PostRepository postRepository;
	private final MediaStorageService mediaStorageService;

	public PostService(PostRepository postRepository, MediaStorageService mediaStorageService) {
		this.postRepository = postRepository;
		this.mediaStorageService = mediaStorageService;
	}

	@Transactional(readOnly = true)
	public List<PostResponse> getFeed() {
		return postRepository.findAllByOrderByCreatedAtDesc().stream().map(this::mapToResponse).collect(Collectors.toList());
	}

	@Transactional
	public PostResponse createPost(String title, String description, List<MultipartFile> files, User owner) {
		if (owner == null) {
			throw new UnauthorizedException("Authentication required");
		}
		if (!StringUtils.hasText(title)) {
			throw new BadRequestException("Title is required");
		}
		String normalizedTitle = title.trim();
		if (normalizedTitle.length() > MAX_TITLE_LENGTH) {
			throw new BadRequestException("Title must be " + MAX_TITLE_LENGTH + " characters or fewer");
		}
		if (!StringUtils.hasText(description)) {
			throw new BadRequestException("Post content is required");
		}
		String normalizedDescription = description.trim();
		if (normalizedDescription.length() > MAX_POST_LENGTH) {
			throw new BadRequestException("Post content must be " + MAX_POST_LENGTH + " characters or fewer");
		}
		List<MultipartFile> mediaFiles = files == null ? List.of() : files;
		if (mediaFiles.size() > MAX_MEDIA) {
			throw new BadRequestException("You can upload up to " + MAX_MEDIA + " media files per post");
		}
		Post post = new Post();
		post.setTitle(normalizedTitle);
		post.setDescription(normalizedDescription);
		post.setAuthor(owner);

		List<StoredMedia> storedMedia = new ArrayList<>();
		for (MultipartFile file : mediaFiles) {
			if (file == null || file.isEmpty()) {
				continue;
			}
			storedMedia.add(mediaStorageService.store(file));
		}
		for (StoredMedia stored : storedMedia) {
			PostMedia media = new PostMedia();
			media.setFileName(stored.fileName());
			media.setMimeType(stored.mimeType());
			media.setUrl(stored.url());
			media.setOriginalFileName(stored.originalFileName());
			media.setType(stored.mimeType().startsWith("video/") ? MediaType.VIDEO : MediaType.IMAGE);
			post.addMedia(media);
		}
		Post saved = postRepository.save(post);
		return mapToResponse(saved);
	}

	private PostResponse mapToResponse(Post post) {
		PostResponse response = new PostResponse();
		response.setId(post.getId());
		response.setTitle(post.getTitle());
		response.setDescription(post.getDescription());
		response.setCreatedAt(post.getCreatedAt());
		response.setUpdatedAt(post.getUpdatedAt());
		PostResponse.AuthorSummary author = new PostResponse.AuthorSummary();
		author.setId(post.getAuthor().getId());
		author.setName(post.getAuthor().getName());
		response.setAuthor(author);
		List<PostMediaResponse> mediaResponses = post.getMedia().stream().map(media -> {
			PostMediaResponse m = new PostMediaResponse();
			m.setId(media.getId());
			m.setUrl(media.getUrl());
			m.setMimeType(media.getMimeType());
			m.setType(media.getType());
			m.setOriginalFileName(media.getOriginalFileName());
			return m;
		}).collect(Collectors.toList());
		response.setMedia(mediaResponses);
		return response;
	}
}
