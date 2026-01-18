package com.example.blog.config;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

	@Value("${app.media.storage-path:uploads}")
	private String mediaStoragePath;

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		Path mediaPath = Paths.get(mediaStoragePath).toAbsolutePath().normalize();
		String location = mediaPath.toUri().toString();
		registry.addResourceHandler("/media/**").addResourceLocations(location).setCachePeriod(3600);
	}
}
