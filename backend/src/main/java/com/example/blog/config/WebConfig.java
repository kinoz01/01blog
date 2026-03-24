package com.example.blog.config;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC configuration that exposes files stored on disk (uploaded media) under a
 * predictable `/media/**` URL so the frontend can render attachments.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

	@Value("${app.media.storage-path:uploads}")
	private String mediaStoragePath;

	/**
	 * Register a resource handler that maps `/media/**` URLs to the physical
	 * directory backing file uploads. We normalise the path to avoid traversal
	 * issues and let Spring cache responses for an hour to reduce disk reads.
	 */
	@Override
	public void addResourceHandlers(@NonNull ResourceHandlerRegistry registry) {
		Path mediaPath = Paths.get(mediaStoragePath).toAbsolutePath().normalize();
		String location = mediaPath.toUri().toString();
		registry.addResourceHandler("/media/**").addResourceLocations(location).setCachePeriod(3600);
	}
}
