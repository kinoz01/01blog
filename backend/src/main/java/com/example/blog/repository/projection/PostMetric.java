package com.example.blog.repository.projection;

import java.util.UUID;

public interface PostMetric {
	UUID getPostId();

	long getCount();
}
