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

/**
 * Handles storing uploaded media on disk, validating MIME types, generating
 * safe filenames, and serving the resulting public URLs back to callers.
 */
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

	/**
	 * Persists a single uploaded file after validating type and extension. The
	 * returned record includes the internal filename and the public URL the
	 * frontend can reference.
	 */
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

	/**
	 * Uses Apache Tika to sniff the MIME type from the file stream.
	 */
	private String detectMimeType(MultipartFile file) {
		try {
			return tika.detect(file.getInputStream(), file.getOriginalFilename());
		} catch (IOException ex) {
			throw new MediaStorageException("Unable to inspect uploaded file", ex);
		}
	}

	/**
	 * Determines the best file extension to use for storage, falling back to the
	 * original filename when Tika cannot determine one.
	 */
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

	/**
	 * Builds the absolute URL exposed to clients. Works for both relative and
	 * absolute base URLs.
	 */
	private String formatPublicUrl(String filename) {
		if (mediaBaseUrl.startsWith("http")) {
			return mediaBaseUrl.endsWith("/") ? mediaBaseUrl + filename : mediaBaseUrl + "/" + filename;
		}
		return mediaBaseUrl.endsWith("/") ? mediaBaseUrl + filename : mediaBaseUrl + "/" + filename;
	}

	/**
	 * SVG files are blocked due to XSS concerns. This helper looks at both the
	 * MIME type and the original extension to catch them.
	 */
	private boolean isSvgFile(String mimeType, String originalName) {
		if (mimeType != null && mimeType.toLowerCase(Locale.ROOT).contains("svg")) {
			return true;
		}
		String extension = StringUtils.getFilenameExtension(originalName);
		return extension != null && extension.equalsIgnoreCase("svg");
	}

	/**
	 * DTO used to return info about the stored file to callers.
	 */
	public record StoredMedia(String fileName, String mimeType, String url, String originalFileName) {
	}

	/**
	 * Deletes a previously stored file if it exists.
	 */
	public void delete(String fileName) {
		if (!StringUtils.hasText(fileName)) {
			return;
		}
		Path target = storagePath.resolve(fileName);
		try {
			Files.deleteIfExists(target);
		} catch (IOException ex) {
			throw new MediaStorageException("Failed to delete media file", ex);
		}
	}
}
