package com.example.blog.repository.projection;

import java.util.UUID;

/**
 * Projection used by Spring Data to fetch aggregated counts (likes/comments)
 * without materialising full Post entities.
 */
public interface PostMetric {
	UUID getPostId();

	long getCount();
}
