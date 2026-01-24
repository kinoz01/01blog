import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';

import { Post } from '../../core/models/post.models';
import { AuthService } from '../../core/services/auth.service';
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
  private allPosts: Post[] = [];
  isLoading = false;
  loadError = '';
  currentUserId: string | null = null;
  composerOpen = false;
  composerError = '';
  submitting = false;
  mediaPreviews: MediaPreview[] = [];
  readonly maxMedia = 10;
  readonly titleMaxLength = 120;
  readonly postMaxLength = 6000;
  private readonly previewLength = 240;
  private readonly destroy$ = new Subject<void>();
  private readonly supportedVideoMimeTypes = new Set(['video/mp4', 'video/webm', 'video/ogg']);
  private readonly supportedVideoExtensions = new Set(['mp4', 'webm', 'ogg']);
  private readonly likesInProgress = new Set<string>();

  private readonly postService = inject(PostService);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly fb = inject(FormBuilder);

  readonly postForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(this.titleMaxLength)]],
    description: ['', [Validators.required, Validators.maxLength(this.postMaxLength)]]
  });

  ngOnInit(): void {
    this.loadPosts();
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.applyOwnerFilter();
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  trackByPost(_index: number, post: Post): string {
    return post.id;
  }

  get titleLength(): number {
    return this.postForm.controls.title.value?.length ?? 0;
  }

  get postLength(): number {
    return this.postForm.controls.description.value?.length ?? 0;
  }

  get remainingMediaSlots(): number {
    return Math.max(this.maxMedia - this.mediaPreviews.length, 0);
  }

  get hasReachedMediaLimit(): boolean {
    return this.remainingMediaSlots <= 0;
  }

  isLikePending(postId: string): boolean {
    return this.likesInProgress.has(postId);
  }

  loadPosts(): void {
    this.isLoading = true;
    this.loadError = '';
    this.postService.getFeed().subscribe({
      next: (posts) => {
        this.allPosts = posts;
        this.applyOwnerFilter();
        this.isLoading = false;
      },
      error: () => {
        this.loadError = 'Unable to load the feed right now.';
        this.isLoading = false;
      }
    });
  }

  openPost(post: Post): void {
    this.router.navigate(['/posts', post.id]);
  }

  openProfile(userId: string, event?: Event): void {
    event?.preventDefault();
    event?.stopPropagation();
    if (!userId) {
      return;
    }
    this.router.navigate(['/users', userId]);
  }

  onCardKeyDown(event: KeyboardEvent, post: Post): void {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      this.openPost(post);
    }
  }

  toggleLike(post: Post, event: Event): void {
    event.stopPropagation();
    event.preventDefault();
    if (!post?.id || this.likesInProgress.has(post.id)) {
      return;
    }
    this.likesInProgress.add(post.id);
    const request$ = post.likedByCurrentUser ? this.postService.unlikePost(post.id) : this.postService.likePost(post.id);
    request$.subscribe({
      next: (updatedPost) => {
        this.likesInProgress.delete(post.id);
        this.applyPostUpdate(updatedPost);
      },
      error: () => {
        this.likesInProgress.delete(post.id);
      }
    });
  }

  getPreview(description: string): string {
    if (!description) {
      return '';
    }
    if (description.length <= this.previewLength) {
      return description;
    }
    return `${description.slice(0, this.previewLength).trim()}…`;
  }

  shouldShowReadMore(description: string): boolean {
    return description?.length > this.previewLength;
  }

  openComposer(): void {
    if (!this.currentUserId) {
      return;
    }
    this.composerOpen = true;
    this.composerError = '';
    this.postForm.reset();
    this.resetMediaPreviews();
  }

  closeComposer(): void {
    this.composerOpen = false;
    this.composerError = '';
    this.postForm.reset();
    this.resetMediaPreviews();
  }

  onFilesSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    this.composerError = '';
    let availableSlots = this.maxMedia - this.mediaPreviews.length;

    for (const file of files) {
      if (availableSlots <= 0) {
        this.composerError = `You can attach up to ${this.maxMedia} media files.`;
        break;
      }
      if (!file.type.startsWith('image/') && !file.type.startsWith('video/')) {
        this.composerError = 'Only image or video files are allowed.';
        continue;
      }
      if (file.type.startsWith('image/') && this.isSvgFile(file)) {
        this.composerError = 'SVG images are not supported.';
        continue;
      }
      if (file.type.startsWith('video/') && !this.isSupportedVideo(file)) {
        this.composerError = 'Unsupported video format.';
        continue;
      }
      const previewUrl = URL.createObjectURL(file);
      this.mediaPreviews.push({
        file,
        previewUrl,
        kind: file.type.startsWith('video/') ? 'video' : 'image'
      });
      availableSlots -= 1;
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
        next: () => {
          this.submitting = false;
          this.closeComposer();
          this.loadPosts();
        },
        error: (error) => {
          this.composerError = this.resolveErrorMessage(error, 'Unable to publish your post right now.');
          this.submitting = false;
        }
      });
  }

  private applyOwnerFilter(): void {
    if (!this.currentUserId) {
      this.posts = [...this.allPosts];
      return;
    }
    this.posts = this.allPosts.filter((post) => post.author.id !== this.currentUserId);
  }

  private applyPostUpdate(updatedPost: Post): void {
    this.allPosts = this.allPosts.map((post) => (post.id === updatedPost.id ? updatedPost : post));
    this.applyOwnerFilter();
  }

  private resetMediaPreviews(): void {
    this.mediaPreviews.forEach((preview) => URL.revokeObjectURL(preview.previewUrl));
    this.mediaPreviews = [];
  }

  private resolveErrorMessage(error: unknown, fallback: string): string {
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }

  private isSupportedVideo(file: File): boolean {
    const mimeType = file.type?.toLowerCase();
    if (mimeType && this.supportedVideoMimeTypes.has(mimeType)) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return !!extension && this.supportedVideoExtensions.has(extension);
  }

  private isSvgFile(file: File): boolean {
    const mimeType = file.type?.toLowerCase() ?? '';
    if (mimeType.includes('svg')) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return extension === 'svg';
  }
}
