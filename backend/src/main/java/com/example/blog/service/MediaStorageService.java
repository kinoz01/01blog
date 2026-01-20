package com.example.blog.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.UUID;

import org.apache.tika.Tika;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.example.blog.exception.MediaStorageException;

@Service
public class MediaStorageService {

	private final Path storagePath;
	private final String mediaBaseUrl;
	private final Tika tika = new Tika();
	private final MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();

	public MediaStorageService(@Value("${app.media.storage-path:uploads}") String mediaPath,
			@Value("${app.media.base-url:/media}") String mediaBaseUrl) {
		this.storagePath = Paths.get(mediaPath).toAbsolutePath().normalize();
		this.mediaBaseUrl = mediaBaseUrl;
		try {
			Files.createDirectories(this.storagePath);
		} catch (IOException ex) {
			throw new MediaStorageException("Could not create media storage directory", ex);
		}
	}

	public StoredMedia store(MultipartFile file) {
		if (file == null || file.isEmpty()) {
			throw new MediaStorageException("Cannot store empty media file");
		}
		String mimeType = detectMimeType(file);
		if (!mimeType.startsWith("image/") && !mimeType.startsWith("video/")) {
			throw new MediaStorageException("Only image and video files are allowed");
		}
		if (isSvgFile(mimeType, file.getOriginalFilename())) {
			throw new MediaStorageException("SVG images are not allowed");
		}
		String extension = resolveExtension(mimeType, file.getOriginalFilename());
		String fileName = UUID.randomUUID() + extension;
		Path target = storagePath.resolve(fileName);
		try {
			Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException ex) {
			throw new MediaStorageException("Failed to store media file", ex);
		}
		String publicUrl = formatPublicUrl(fileName);
		return new StoredMedia(fileName, mimeType, publicUrl, file.getOriginalFilename());
	}

	private String detectMimeType(MultipartFile file) {
		try {
			return tika.detect(file.getInputStream(), file.getOriginalFilename());
		} catch (IOException ex) {
			throw new MediaStorageException("Unable to inspect uploaded file", ex);
		}
	}

	private String resolveExtension(String mimeType, String originalName) {
		try {
			String extension = mimeTypes.forName(mimeType).getExtension();
			if (StringUtils.hasText(extension)) {
				return extension;
			}
		} catch (MimeTypeException ignored) {
		}
		String fallback = StringUtils.getFilenameExtension(originalName);
		return fallback == null || fallback.isBlank() ? "" : "." + fallback;
	}

	private String formatPublicUrl(String filename) {
		if (mediaBaseUrl.startsWith("http")) {
			return mediaBaseUrl.endsWith("/") ? mediaBaseUrl + filename : mediaBaseUrl + "/" + filename;
		}
		return mediaBaseUrl.endsWith("/") ? mediaBaseUrl + filename : mediaBaseUrl + "/" + filename;
	}

	private boolean isSvgFile(String mimeType, String originalName) {
		if (mimeType != null && mimeType.toLowerCase(Locale.ROOT).contains("svg")) {
			return true;
		}
		String extension = StringUtils.getFilenameExtension(originalName);
		return extension != null && extension.equalsIgnoreCase("svg");
	}

	public record StoredMedia(String fileName, String mimeType, String url, String originalFileName) {
	}
}
