import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';

import { Post } from '../../core/models/post.models';
import { PostService } from '../../core/services/post.service';

interface MediaPreview {
  file: File;
  previewUrl: string;
  kind: 'image' | 'video';
}

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent implements OnDestroy, OnInit {
  posts: Post[] = [];
  isLoading = false;
  composerOpen = false;
  submitting = false;
  loadError = '';
  composerError = '';
  mediaPreviews: MediaPreview[] = [];
  private readonly supportedVideoMimeTypes = new Set(['video/mp4', 'video/webm', 'video/ogg']);
  private readonly supportedVideoExtensions = new Set(['mp4', 'webm', 'ogg']);

  private readonly fb = inject(FormBuilder);
  private readonly postService = inject(PostService);

  readonly postForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(120)]],
    description: ['', [Validators.required, Validators.maxLength(2000)]]
  });

  ngOnInit(): void {
    this.loadPosts();
  }

  ngOnDestroy(): void {
    this.resetMediaPreviews();
  }

  trackByPost(_index: number, post: Post): string {
    return post.id;
  }

  trackByMedia(_index: number, media: MediaPreview): string {
    return media.previewUrl;
  }

  loadPosts(): void {
    this.isLoading = true;
    this.postService.getFeed().subscribe({
      next: (posts) => {
        this.posts = posts;
        this.isLoading = false;
        this.loadError = '';
      },
      error: () => {
        this.loadError = 'Unable to load the feed right now.';
        this.isLoading = false;
      }
    });
  }

  openComposer(): void {
    this.composerOpen = true;
  }

  closeComposer(): void {
    this.composerOpen = false;
    this.postForm.reset();
    this.composerError = '';
    this.resetMediaPreviews();
  }

  onFilesSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    this.composerError = '';

    for (const file of files) {
      if (this.mediaPreviews.length >= 10) {
        this.composerError = 'You can attach up to 10 media files.';
        break;
      }
      if (!file.type.startsWith('image/') && !file.type.startsWith('video/')) {
        this.composerError = 'Only image or video files are allowed.';
        continue;
      }
      if (file.type.startsWith('video/') && !this.isSupportedVideo(file)) {
        this.composerError = 'Unsupported video format. Please use MP4, WebM, or Ogg files.';
        continue;
      }
      const previewUrl = URL.createObjectURL(file);
      this.mediaPreviews.push({
        file,
        previewUrl,
        kind: file.type.startsWith('video/') ? 'video' : 'image'
      });
    }

    if (input) {
      input.value = '';
    }
  }

  removeMedia(index: number): void {
    const [removed] = this.mediaPreviews.splice(index, 1);
    if (removed) {
      URL.revokeObjectURL(removed.previewUrl);
    }
  }

  submitPost(): void {
    if (this.postForm.invalid) {
      this.postForm.markAllAsTouched();
      return;
    }

    const { title, description } = this.postForm.getRawValue();
    this.submitting = true;
    this.composerError = '';

    this.postService
      .createPost({ title, description, media: this.mediaPreviews.map((preview) => preview.file) })
      .subscribe({
        next: (post) => {
          this.posts = [post, ...this.posts];
          this.submitting = false;
          this.closeComposer();
        },
        error: (error) => {
          const message =
            typeof error === 'string'
              ? error
              : error?.error?.message ?? 'Unable to publish your post right now.';
          this.composerError = message;
          this.submitting = false;
        }
      });
  }

  private resetMediaPreviews(): void {
    this.mediaPreviews.forEach((preview) => URL.revokeObjectURL(preview.previewUrl));
    this.mediaPreviews = [];
  }

  private isSupportedVideo(file: File): boolean {
    const mimeType = file.type?.toLowerCase();
    if (mimeType && this.supportedVideoMimeTypes.has(mimeType)) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return !!extension && this.supportedVideoExtensions.has(extension);
  }
}
