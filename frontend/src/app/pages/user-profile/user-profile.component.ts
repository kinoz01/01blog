import { CommonModule } from '@angular/common';
import { Component, HostListener, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, catchError, of, switchMap, takeUntil } from 'rxjs';

import { Post, PostMedia } from '../../core/models/post.models';
import { UserProfileDetails } from '../../core/models/user.models';
import { UserService } from '../../core/services/user.service';
import { PostService } from '../../core/services/post.service';
import { AuthService } from '../../core/services/auth.service';
import { ReportService } from '../../core/services/report.service';
import { ConfirmationService } from '../../core/services/confirmation.service';

interface MediaPreview {
  file: File;
  previewUrl: string;
  kind: 'image' | 'video';
}

interface EditableMedia extends PostMedia {
  markedForRemoval: boolean;
}

@Component({
  selector: 'app-user-profile',
  standalone: true,
  imports: [CommonModule, RouterLink, ReactiveFormsModule],
  templateUrl: './user-profile.component.html',
  styleUrl: './user-profile.component.scss'
})
// Profile page combining read-only and owner-only post management capabilities.
export class UserProfileComponent implements OnDestroy, OnInit {
  profile: UserProfileDetails | null = null;
  posts: Post[] = [];
  isLoading = true;
  error = '';
  postActionError = '';
  composerOpen = false;
  composerError = '';
  submitting = false;
  editingPost: Post | null = null;
  menuOpenFor: string | null = null;
  deleteInProgressId: string | null = null;
  currentUserId: string | null = null;
  currentUserRole: 'USER' | 'ADMIN' | null = null;
  mediaPreviews: MediaPreview[] = [];
  existingMedia: EditableMedia[] = [];
  subscriptionInProgress = false;
  subscriptionError = '';
  reportModalOpen = false;
  reportSubmitting = false;
  reportError = '';
  readonly maxMedia = 10;
  readonly titleMaxLength = 120;
  readonly postMaxLength = 6000;
  readonly reportReasonMax = 1000;
  private readonly previewLength = 240;
  private readonly likesInProgress = new Set<string>();

  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly userService = inject(UserService);
  private readonly postService = inject(PostService);
  private readonly authService = inject(AuthService);
  private readonly reportService = inject(ReportService);
  private readonly fb = inject(FormBuilder);
  private readonly destroy$ = new Subject<void>();
  private readonly supportedVideoMimeTypes = new Set(['video/mp4', 'video/webm', 'video/ogg']);
  private readonly supportedVideoExtensions = new Set(['mp4', 'webm', 'ogg']);
  private readonly confirmationService = inject(ConfirmationService);

  // Composer form used for both creating and editing posts.
  readonly postForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(this.titleMaxLength)]],
    description: ['', [Validators.required, Validators.maxLength(this.postMaxLength)]]
  });

  // Report modal form for describing profile abuse.
  readonly reportForm = this.fb.nonNullable.group({
    reason: ['', [Validators.required, Validators.minLength(5), Validators.maxLength(this.reportReasonMax)]]
  });

  ngOnInit(): void {
    // Keep track of the logged-in user so we can tailor available actions.
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.currentUserRole = user?.role ?? null;
    });

    // React to route changes and fetch the corresponding profile.
    this.route.paramMap
      .pipe(
        takeUntil(this.destroy$),
        switchMap((params) => {
          const userId = params.get('userId');
          if (!userId) {
            this.isLoading = false;
            this.redirectToUserDirectory();
            return of(null);
          }
          return this.loadProfile(userId);
        })
      )
      .subscribe((profile) => {
        this.profile = profile;
        this.posts = profile?.posts ?? [];
        this.isLoading = false;
      });
  }
  // Clean up subscriptions and revoke blob URLs when the component is destroyed to prevent memory leaks.
  ngOnDestroy(): void {
    this.resetMediaPreviews();
    this.destroy$.next();
    this.destroy$.complete();
  }

  get isProfileOwner(): boolean {
    return !!this.profile && !!this.currentUserId && this.profile.id === this.currentUserId;
  }

  get titleLength(): number {
    return this.postForm.controls.title.value?.length ?? 0;
  }

  get postLength(): number {
    return this.postForm.controls.description.value?.length ?? 0;
  }

  get isEditing(): boolean {
    return !!this.editingPost;
  }

  get canReportProfile(): boolean {
    return (
      !!this.profile &&
      !this.isProfileOwner &&
      this.profile.role !== 'ADMIN' &&
      this.currentUserRole !== 'ADMIN'
    );
  }

  get hasReportedProfile(): boolean {
    return !!this.profile && this.reportService.hasReportedUser(this.profile.id, this.currentUserId);
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

  openPost(post: Post, event?: Event): void {
    event?.preventDefault();
    if (!post?.id) {
      return;
    }
    this.router.navigate(['/posts', post.id]);
  }

  onPostKeyDown(event: KeyboardEvent, post: Post): void {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      this.openPost(post);
    }
  }

  toggleLike(post: Post, event: MouseEvent): void {
    // Prevent duplicate requests and propagate the like/unlike change to the feed/post list.
    event.preventDefault();
    event.stopPropagation();
    if (!post?.id || this.likesInProgress.has(post.id)) {
      return;
    }
    this.likesInProgress.add(post.id);
    const request$ = post.likedByCurrentUser
      ? this.postService.unlikePost(post.id)
      : this.postService.likePost(post.id);
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

  trackByPost(_index: number, post: Post): string {
    return post.id;
  }

  trackByExistingMedia(_index: number, media: EditableMedia): string {
    return media.id;
  }

  trackByMedia(_index: number, media: MediaPreview): string {
    return media.previewUrl;
  }

  isLikePending(postId: string): boolean {
    return this.likesInProgress.has(postId);
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

  async toggleSubscription(): Promise<void> {
    // Subscribe or unsubscribe from the profile owner to control feed content.
    if (!this.profile || this.isProfileOwner || this.subscriptionInProgress) {
      return;
    }
    const isUnsubscribing = this.profile.subscribed;
    const confirmed = await this.confirmationService.confirm({
      title: isUnsubscribing ? 'Unsubscribe' : 'Subscribe',
      message: isUnsubscribing
        ? `Stop receiving updates from ${this.profile.name}?`
        : `Subscribe to ${this.profile.name}'s updates?`,
      confirmLabel: isUnsubscribing ? 'Unsubscribe' : 'Subscribe',
      tone: isUnsubscribing ? 'danger' : 'primary'
    });
    if (!confirmed) {
      return;
    }
    this.subscriptionError = '';
    this.subscriptionInProgress = true;
    const request = this.profile.subscribed
      ? this.userService.unsubscribe(this.profile.id)
      : this.userService.subscribe(this.profile.id);
    request.subscribe({
      next: () => {
        if (this.profile) {
          this.profile = { ...this.profile, subscribed: !this.profile.subscribed };
        }
        this.subscriptionInProgress = false;
      },
      error: (error) => {
        this.subscriptionError = this.resolveErrorMessage(
          error,
          'Unable to update your subscription right now.'
        );
        this.subscriptionInProgress = false;
      }
    });
  }

  openReportModal(): void {
    // Only non-owners who haven't already filed a report may open the modal.
    if (!this.profile || this.isProfileOwner || this.hasReportedProfile) {
      return;
    }
    this.reportForm.reset();
    this.reportModalOpen = true;
    this.reportError = '';
  }

  closeReportModal(): void {
    // Reset report modal state so each invocation starts clean.
    this.reportModalOpen = false;
    this.reportError = '';
    this.reportSubmitting = false;
    this.reportForm.reset();
  }

  async submitReport(): Promise<void> {
    // Validate the reason and send it to the backend (with a confirm guard).
    if (!this.profile || this.hasReportedProfile) {
      return;
    }
    if (this.reportForm.invalid) {
      this.reportForm.markAllAsTouched();
      return;
    }
    const confirmed = await this.confirmationService.confirm({
      title: 'Report profile',
      message: 'Submit this report for review?',
      confirmLabel: 'Submit report',
      tone: 'danger'
    });
    if (!confirmed) {
      return;
    }
    this.reportSubmitting = true;
    this.reportError = '';
    const reason = this.reportForm.controls.reason.value ?? '';
    this.reportService.reportUser(this.profile.id, reason, this.currentUserId).subscribe({
      next: () => {
        this.reportSubmitting = false;
        this.closeReportModal();
      },
      error: () => {
        this.reportError = 'Unable to submit your report right now.';
        this.reportSubmitting = false;
      }
    });
  }

  get reportReasonLength(): number {
    return this.reportForm.controls.reason.value?.length ?? 0;
  }

  get reportReasonHasError(): boolean {
    const control = this.reportForm.controls.reason;
    return control.invalid && (control.dirty || control.touched);
  }

  openComposer(post?: Post): void {
    // Opens the composer to edit an existing post, preloading its content/media.
    if (!post) {
      return;
    }
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
    // Reset composer state whether cancelling or after successful submit.
    this.composerOpen = false;
    this.editingPost = null;
    this.postForm.reset();
    this.composerError = '';
    this.menuOpenFor = null;
    this.existingMedia = [];
    this.resetMediaPreviews();
  }

  onFilesSelected(event: Event): void {
    // Handle newly selected files, enforcing type/limit restrictions.
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

    for (const file of files) { // Process each file, skipping invalid ones but allowing valid files until the limit is reached.
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
    // Removes a newly added file before submission, releasing blob URLs.
    const [removed] = this.mediaPreviews.splice(index, 1);
    if (removed) {
      URL.revokeObjectURL(removed.previewUrl);
    }
    this.composerError = '';
  }

  submitPost(): void {
    // Validates and dispatches the create/update post call depending on context.
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

    this.postService
      .createPost({ title, description, media: this.mediaPreviews.map((preview) => preview.file) })
      .subscribe({
        next: (post) => {
          this.posts = [post, ...this.posts];
          if (this.profile) {
            this.profile = { ...this.profile, postCount: (this.profile.postCount ?? 0) + 1, posts: this.posts };
          }
          this.submitting = false;
          this.closeComposer();
        },
        error: (error) => {
          this.composerError = this.resolveErrorMessage(error, 'Unable to publish your post right now.');
          this.submitting = false;
        }
      });
  }

  toggleMenu(post: Post, event: MouseEvent): void {
    // Opens a contextual menu for edit/delete; clicking the row shouldn’t trigger navigation.
    event.preventDefault();
    event.stopPropagation();
    this.menuOpenFor = this.menuOpenFor === post.id ? null : post.id;
  }

  editPost(post: Post, event: MouseEvent): void {
    // Preloads the composer with the post being edited.
    event.preventDefault();
    event.stopPropagation();
    this.menuOpenFor = null;
    this.openComposer(post);
  }

  async deletePost(post: Post, event: MouseEvent): Promise<void> {
    // Performs deletion with confirmation and updates in-memory state.
    event.preventDefault();
    event.stopPropagation();
    if (this.deleteInProgressId === post.id) {
      return;
    }
    const confirmed = await this.confirmationService.confirm({
      title: 'Delete post',
      message: 'Delete this post? This action cannot be undone.',
      confirmLabel: 'Delete post',
      tone: 'danger'
    });
    if (!confirmed) {
      return;
    }
    this.deleteInProgressId = post.id;
    this.postActionError = '';
    this.postService.deletePost(post.id).subscribe({
      next: () => {
        this.posts = this.posts.filter((item) => item.id !== post.id);
        if (this.profile) {
          this.profile = {
            ...this.profile,
            postCount: Math.max(this.profile.postCount - 1, 0),
            posts: this.posts
          };
        }
        this.deleteInProgressId = null;
        this.menuOpenFor = null;
      },
      error: (error) => {
        this.postActionError = this.resolveErrorMessage(error, 'Unable to delete the post right now.');
        this.deleteInProgressId = null;
      }
    });
  }

  // Checks if the current user is the author of the post to conditionally show edit/delete options.
  isOwner(post: Post): boolean {
    return !!this.currentUserId && post.author.id === this.currentUserId;
  }

  toggleExistingMedia(media: EditableMedia): void { // Marks/unmarks existing media for removal when editing a post.
    media.markedForRemoval = !media.markedForRemoval;
  }

  // Closes any open menus when clicking outside to ensure only one menu is open at a time.
  @HostListener('document:click')
  closeMenus(): void {
    this.menuOpenFor = null;
  }
  
  // method for generating user initials for avatar placeholders when no profile picture is available.
  getInitials(name: string): string {
    if (!name) {
      return '?';
    }
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) {
      return parts[0].slice(0, 2).toUpperCase();
    }
    const first = parts[0]?.[0] ?? '';
    const last = parts[parts.length - 1]?.[0] ?? '';
    const initials = `${first}${last}`.trim();
    return initials ? initials.toUpperCase() : parts[0].slice(0, 2).toUpperCase();
  }

  // Additional helper methods for error handling, media validation, and state updates.
  private loadProfile(userId: string) {
    this.error = '';
    this.isLoading = true;
    return this.userService.getProfile(userId).pipe(
      catchError((err) => {
        if (this.shouldRedirectToUserDirectory(err)) {
          this.isLoading = false;
          this.redirectToUserDirectory();
          return of(null);
        }
        const message =
          typeof err === 'string'
            ? err
            : err?.error?.message ?? 'Unable to load that profile right now.';
        this.error = message;
        this.isLoading = false;
        return of(null);
      })
    );
  }

  private resetMediaPreviews(): void {
    // Release temporary URLs so the browser can reclaim memory.
    this.mediaPreviews.forEach((preview) => URL.revokeObjectURL(preview.previewUrl));
    this.mediaPreviews = [];
  }

  private shouldRedirectToUserDirectory(error: unknown): boolean {
    const status = (error as { status?: number })?.status;
    return status === 404 || status === 400;
  }

  private redirectToUserDirectory(): void {
    this.router.navigate(['/users']);
  }

  private updateExistingPost(post: Post, title: string, description: string): void {
    // Sends updates for an existing post, tracking removed media and newly added files.
    const removeMediaIds = this.existingMedia.filter((media) => media.markedForRemoval).map((media) => media.id);
    const mediaFiles = this.mediaPreviews.map((preview) => preview.file);
    this.postService.updatePost(post.id, { title, description, removeMediaIds, media: mediaFiles }).subscribe({
      next: (updated) => {
        this.applyPostUpdate(updated);
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
    // Central helper to convert unknown API errors into readable messages.
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }

  private isSupportedVideo(file: File): boolean {
    // Restrict uploads to video formats we know the backend can handle.
    const mimeType = file.type?.toLowerCase();
    if (mimeType && this.supportedVideoMimeTypes.has(mimeType)) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return !!extension && this.supportedVideoExtensions.has(extension);
  }

  private isSvgFile(file: File): boolean {
    // Blocks SVG uploads due to potential XSS issues.
    const mimeType = file.type?.toLowerCase() ?? '';
    if (mimeType.includes('svg')) {
      return true;
    }
    const extension = file.name?.split('.').pop()?.toLowerCase();
    return extension === 'svg';
  }

  private applyPostUpdate(updatedPost: Post): void {
    // Updates local post lists so UI reflects edits/like counts.
    let didUpdate = false;
    this.posts = this.posts.map((item) => {
      if (item.id === updatedPost.id) {
        didUpdate = true;
        return updatedPost;
      }
      return item;
    });
    if (didUpdate && this.profile) {
      this.profile = { ...this.profile, posts: this.posts };
    }
  }
}
