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
// Main feed page showing posts and exposing the composer for authenticated users.
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

  // Composer form for creating new posts with title and description validation.
  readonly postForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(this.titleMaxLength)]],
    description: ['', [Validators.required, Validators.maxLength(this.postMaxLength)]]
  });

  ngOnInit(): void {
    // Load posts immediately and react to auth changes so we can filter out the user's own posts.
    this.loadPosts();
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.applyOwnerFilter();
    });
  }

  ngOnDestroy(): void {
    // Clean up subscriptions to avoid memory leaks.
    this.destroy$.next();
    this.destroy$.complete();
  }

  trackByPost(_index: number, post: Post): string {
    // trackBy for ngFor to avoid rerendering unchanged cards.
    return post.id;
  }

  get titleLength(): number {
    // Used to display current title length to enforce limits.
    return this.postForm.controls.title.value?.length ?? 0;
  }

  get postLength(): number {
    // Used for description character counter.
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
    // Fetch the feed from the server and show loading/error state in the UI.
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
    // Navigates to the post detail view when clicking a card.
    this.router.navigate(['/posts', post.id]);
  }

  openProfile(userId: string, event?: Event): void {
    // Allow name/avatar clicks to navigate to the author profile without triggering card click.
    event?.preventDefault();
    event?.stopPropagation();
    if (!userId) {
      return;
    }
    this.router.navigate(['/users', userId]);
  }

  onCardKeyDown(event: KeyboardEvent, post: Post): void {
    // Provide keyboard accessibility so Enter/Space opens the post.
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      this.openPost(post);
    }
  }

  toggleLike(post: Post, event: Event): void {
    // Optimistically toggle likes while preventing navigation when pressing the icon.
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
    // Opens the composer modal; only allowed when logged in.
    if (!this.currentUserId) {
      return;
    }
    this.composerOpen = true;
    this.composerError = '';
    this.postForm.reset();
    this.resetMediaPreviews();
  }

  closeComposer(): void {
    // Resets composer state so it starts fresh next time.
    this.composerOpen = false;
    this.composerError = '';
    this.postForm.reset();
    this.resetMediaPreviews();
  }

  onFilesSelected(event: Event): void {
    // Handles file input changes, enforces allowed types, and builds previews.
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
    // Removes a selected media preview and releases the blob URL.
    const [removed] = this.mediaPreviews.splice(index, 1);
    if (removed) {
      URL.revokeObjectURL(removed.previewUrl);
    }
  }

  submitPost(): void {
    // Validates and sends the new post to the backend, showing errors when needed.
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
    // Remove the current user's posts from the feed so they don't see duplicates with their profile.
    if (!this.currentUserId) {
      this.posts = [...this.allPosts];
      return;
    }
    this.posts = this.allPosts.filter((post) => post.author.id !== this.currentUserId);
  }

  private applyPostUpdate(updatedPost: Post): void {
    // Utility to update the in-memory posts when a like or interaction changes a single post.
    this.allPosts = this.allPosts.map((post) => (post.id === updatedPost.id ? updatedPost : post));
    this.applyOwnerFilter();
  }

  private resetMediaPreviews(): void {
    // Ensures we don’t leak blob URLs when clearing the composer.
    this.mediaPreviews.forEach((preview) => URL.revokeObjectURL(preview.previewUrl));
    this.mediaPreviews = [];
  }

  private resolveErrorMessage(error: unknown, fallback: string): string {
    // Normalizes unknown API errors to a friendly string.
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }

  private isSupportedVideo(file: File): boolean {
    // Avoids uploading unsupported video formats by checking both mime and extension.
    const mimeType = file.type?.toLowerCase();
    if (mimeType && this.supportedVideoMimeTypes.has(mimeType)) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return !!extension && this.supportedVideoExtensions.has(extension);
  }

  private isSvgFile(file: File): boolean {
    // SVGs are blocked due to potential script injection; this helper catches them.
    const mimeType = file.type?.toLowerCase() ?? '';
    if (mimeType.includes('svg')) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return extension === 'svg';
  }
}
