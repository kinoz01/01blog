import { CommonModule } from '@angular/common';
import { Component, HostListener, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';

import { Post, PostMedia } from '../../core/models/post.models';
import { AuthService } from '../../core/services/auth.service';
import { PostService } from '../../core/services/post.service';

interface MediaPreview {
  file: File;
  previewUrl: string;
  kind: 'image' | 'video';
}

interface EditableMedia extends PostMedia {
  markedForRemoval: boolean;
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
  editingPost: Post | null = null;
  loadError = '';
  postActionError = '';
  composerError = '';
  menuOpenFor: string | null = null;
  deleteInProgressId: string | null = null;
  currentUserId: string | null = null;
  mediaPreviews: MediaPreview[] = [];
  existingMedia: EditableMedia[] = [];
  private readonly supportedVideoMimeTypes = new Set(['video/mp4', 'video/webm', 'video/ogg']);
  private readonly supportedVideoExtensions = new Set(['mp4', 'webm', 'ogg']);
  private readonly destroy$ = new Subject<void>();
  private readonly previewLength = 240;
  readonly maxMedia = 10;

  private readonly fb = inject(FormBuilder);
  private readonly postService = inject(PostService);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  readonly postForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(120)]],
    description: ['', [Validators.required, Validators.maxLength(6000)]]
  });
  readonly titleMaxLength = 120;
  readonly postMaxLength = 6000;

  get titleLength(): number {
    return this.postForm.controls.title.value?.length ?? 0;
  }

  get postLength(): number {
    return this.postForm.controls.description.value?.length ?? 0;
  }

  get isEditing(): boolean {
    return !!this.editingPost;
  }

  get activeExistingMediaCount(): number {
    return this.existingMedia.filter((media) => !media.markedForRemoval).length;
  }

  get remainingMediaSlots(): number {
    return Math.max(this.maxMedia - this.activeExistingMediaCount - this.mediaPreviews.length, 0);
  }

  get hasReachedMediaLimit(): boolean {
    return this.remainingMediaSlots <= 0;
  }

  ngOnInit(): void {
    this.loadPosts();
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
    });
  }

  ngOnDestroy(): void {
    this.resetMediaPreviews();
    this.destroy$.next();
    this.destroy$.complete();
  }

  trackByPost(_index: number, post: Post): string {
    return post.id;
  }

  trackByExistingMedia(_index: number, media: EditableMedia): string {
    return media.id;
  }

  trackByMedia(_index: number, media: MediaPreview): string {
    return media.previewUrl;
  }

  loadPosts(): void {
    this.isLoading = true;
    this.postActionError = '';
    this.menuOpenFor = null;
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

  openComposer(post?: Post): void {
    this.composerOpen = true;
    this.composerError = '';
    this.menuOpenFor = null;
    this.resetMediaPreviews();
    this.existingMedia = [];
    if (post) {
      this.editingPost = post;
      this.postForm.setValue({
        title: post.title,
        description: post.description
      });
      this.existingMedia = (post.media ?? []).map((media) => ({
        ...media,
        markedForRemoval: false
      }));
      return;
    }
    this.editingPost = null;
    this.postForm.reset();
  }

  closeComposer(): void {
    this.composerOpen = false;
    this.editingPost = null;
    this.postForm.reset();
    this.composerError = '';
    this.menuOpenFor = null;
     this.existingMedia = [];
    this.resetMediaPreviews();
  }

  onFilesSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    this.composerError = '';
    let availableSlots = this.maxMedia - this.activeExistingMediaCount - this.mediaPreviews.length;

    if (availableSlots <= 0) {
      this.composerError = `You can attach up to ${this.maxMedia} media files. Remove an attachment before adding more.`;
      if (input) {
        input.value = '';
      }
      return;
    }

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
        this.composerError = 'SVG images are not supported. Convert the file to PNG or JPEG first.';
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
    this.composerError = '';
  }

  submitPost(): void {
    if (this.postForm.invalid) {
      this.postForm.markAllAsTouched();
      return;
    }

    const { title, description } = this.postForm.getRawValue();
    this.submitting = true;
    this.composerError = '';

    if (this.isEditing && this.editingPost) {
      this.updateExistingPost(this.editingPost, title, description);
      return;
    }

    this.postService.createPost({ title, description, media: this.mediaPreviews.map((preview) => preview.file) }).subscribe({
      next: (post) => {
        this.posts = [post, ...this.posts];
        this.submitting = false;
        this.closeComposer();
      },
      error: (error) => {
        this.composerError = this.resolveErrorMessage(error, 'Unable to publish your post right now.');
        this.submitting = false;
      }
    });
  }

  openPost(post: Post): void {
    this.router.navigate(['/posts', post.id]);
  }

  onCardKeyDown(event: KeyboardEvent, post: Post): void {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      this.openPost(post);
    }
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

  toggleMenu(post: Post, event: MouseEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.menuOpenFor = this.menuOpenFor === post.id ? null : post.id;
  }

  editPost(post: Post, event: MouseEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.menuOpenFor = null;
    this.openComposer(post);
  }

  deletePost(post: Post, event: MouseEvent): void {
    event.preventDefault();
    event.stopPropagation();
    if (this.deleteInProgressId === post.id) {
      return;
    }
    const confirmed = confirm('Delete this post? This action cannot be undone.');
    if (!confirmed) {
      return;
    }
    this.deleteInProgressId = post.id;
    this.postActionError = '';
    this.postService.deletePost(post.id).subscribe({
      next: () => {
        this.posts = this.posts.filter((item) => item.id !== post.id);
        this.deleteInProgressId = null;
        this.menuOpenFor = null;
      },
      error: (error) => {
        this.postActionError = this.resolveErrorMessage(error, 'Unable to delete the post right now.');
        this.deleteInProgressId = null;
      }
    });
  }

  isOwner(post: Post): boolean {
    return !!this.currentUserId && post.author.id === this.currentUserId;
  }

  toggleExistingMedia(media: EditableMedia): void {
    media.markedForRemoval = !media.markedForRemoval;
  }

  private resetMediaPreviews(): void {
    this.mediaPreviews.forEach((preview) => URL.revokeObjectURL(preview.previewUrl));
    this.mediaPreviews = [];
  }

  private updateExistingPost(post: Post, title: string, description: string): void {
    const removeMediaIds = this.existingMedia.filter((media) => media.markedForRemoval).map((media) => media.id);
    const mediaFiles = this.mediaPreviews.map((preview) => preview.file);
    this.postService.updatePost(post.id, { title, description, removeMediaIds, media: mediaFiles }).subscribe({
      next: (updated) => {
        this.posts = this.posts.map((item) => (item.id === updated.id ? updated : item));
        this.submitting = false;
        this.closeComposer();
      },
      error: (error) => {
        this.composerError = this.resolveErrorMessage(error, 'Unable to update your post right now.');
        this.submitting = false;
      }
    });
  }

  private resolveErrorMessage(error: unknown, fallback: string): string {
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }

  @HostListener('document:click')
  closeMenus(): void {
    this.menuOpenFor = null;
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
