import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, of, switchMap, takeUntil, catchError } from 'rxjs';

import { Post, PostComment } from '../../core/models/post.models';
import { PostService } from '../../core/services/post.service';
import { AuthService } from '../../core/services/auth.service';
import { ReportService } from '../../core/services/report.service';
import { ConfirmationService } from '../../core/services/confirmation.service';

@Component({
  selector: 'app-post-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, ReactiveFormsModule],
  templateUrl: './post-detail.component.html',
  styleUrl: './post-detail.component.scss'
})
// Post detail view responsible for displaying a single post, comments, and moderation actions.
export class PostDetailComponent implements OnDestroy, OnInit {
  post: Post | null = null;
  isLoading = true;
  error = '';
  private currentUserId: string | null = null;
  private currentUserRole: 'USER' | 'ADMIN' | null = null;
  commentError = '';
  commentSubmitting = false;
  likeInProgress = false;
  readonly commentMaxLength = 1000;
  reportModalOpen = false;
  reportSubmitting = false;
  reportError = '';
  readonly reportMaxLength = 1000;
  private readonly commentDeletionState = new Set<string>();

  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly postService = inject(PostService);
  private readonly authService = inject(AuthService);
  private readonly reportService = inject(ReportService);
  private readonly fb = inject(FormBuilder);
  private readonly destroy$ = new Subject<void>();
  private readonly confirmationService = inject(ConfirmationService);

  // Form users fill out to leave a comment.
  readonly commentForm = this.fb.nonNullable.group({
    content: ['', [Validators.required, Validators.maxLength(this.commentMaxLength)]]
  });

  // Report modal form for describing why the post should be moderated.
  readonly reportForm = this.fb.nonNullable.group({
    reason: ['', [Validators.required, Validators.minLength(5), Validators.maxLength(this.reportMaxLength)]]
  });

  ngOnInit(): void {
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.currentUserRole = user?.role ?? null;
    });

    this.route.paramMap
      .pipe(
        takeUntil(this.destroy$),
        switchMap((params) => {
          const postId = params.get('postId');
          if (!postId) {
            this.isLoading = false;
            this.redirectToHome();
            return of(null);
          }
          this.isLoading = true;
          this.error = '';
          return this.postService.getPost(postId).pipe(
            catchError((err) => {
              if (this.shouldRedirectToHome(err)) {
                this.isLoading = false;
                this.redirectToHome();
                return of(null);
              }
              const message =
                typeof err === 'string'
                  ? err
                  : err?.error?.message ?? 'Unable to load the post right now.';
              this.error = message;
              return of(null);
            })
          );
        })
      )
      .subscribe((post) => {
        this.post = post ? { ...post, comments: post.comments ?? [] } : null;
        this.isLoading = false;
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  isOwner(): boolean {
    return !!this.post && !!this.currentUserId && this.post.author.id === this.currentUserId;
  }

  toggleLike(): void {
    // Prevent rapid double clicks; toggles between like/unlike endpoints.
    if (!this.post || this.likeInProgress) {
      return;
    }
    this.likeInProgress = true;
    const request$ = this.post.likedByCurrentUser
      ? this.postService.unlikePost(this.post.id)
      : this.postService.likePost(this.post.id);
    request$.subscribe({
      next: (updatedPost) => {
        const comments = this.post?.comments ?? [];
        this.post = { ...updatedPost, comments };
        this.likeInProgress = false;
      },
      error: () => {
        this.likeInProgress = false;
      }
    });
  }

  openReportModal(): void {
    // Only non-owners who haven't already reported may open the modal.
    if (this.isOwner() || this.hasReportedPost()) {
      return;
    }
    this.reportForm.reset();
    this.reportModalOpen = true;
    this.reportError = '';
  }

  closeReportModal(): void {
    // Reset the form state on close so it's clean next time.
    this.reportModalOpen = false;
    this.reportForm.reset();
    this.reportSubmitting = false;
    this.reportError = '';
  }

  async submitReport(): Promise<void> {
    // Validates, asks for confirmation, then submits a report.
    if (!this.post || this.hasReportedPost()) {
      return;
    }
    if (this.reportForm.invalid) {
      this.reportForm.markAllAsTouched();
      return;
    }
    const confirmed = await this.confirmationService.confirm({
      title: 'Report post',
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
    this.reportService.reportPost(this.post.id, reason, this.currentUserId).subscribe({
      next: () => {
        this.reportSubmitting = false;
        this.closeReportModal();
      },
      error: () => {
        this.reportError = 'Unable to send your report right now.';
        this.reportSubmitting = false;
      }
    });
  }

  submitComment(): void {
    // Adds a comment to the post; invalid forms are marked touched to show errors.
    if (!this.post) {
      return;
    }
    if (this.commentForm.invalid) {
      this.commentForm.markAllAsTouched();
      return;
    }
    const { content } = this.commentForm.getRawValue();
    this.commentSubmitting = true;
    this.commentError = '';
    this.postService.addComment(this.post.id, content).subscribe({
      next: (comment) => {
        if (!this.post) {
          this.commentSubmitting = false;
          return;
        }
        const comments = [...(this.post.comments ?? []), comment];
        this.post = { ...this.post, comments, commentCount: this.post.commentCount + 1 };
        this.commentForm.reset();
        this.commentSubmitting = false;
      },
      error: (err) => {
        this.commentError = this.resolveErrorMessage(err, 'Unable to add your comment right now.');
        this.commentSubmitting = false;
      }
    });
  }

  get commentLength(): number {
    return this.commentForm.controls.content.value?.length ?? 0;
  }

  get reportReasonLength(): number {
    return this.reportForm.controls.reason.value?.length ?? 0;
  }

  get reportReasonHasError(): boolean {
    const control = this.reportForm.controls.reason;
    return control.invalid && (control.dirty || control.touched);
  }

  canReportPost(): boolean {
    // Viewer cannot report their own post, and we block admins from reporting admins.
    if (!this.post || this.isOwner()) {
      return false;
    }
    if (this.currentUserRole === 'ADMIN') {
      return false;
    }
    return this.post.author.role !== 'ADMIN';
  }

  hasReportedPost(): boolean {
    // Checks the client cache that tracks which posts this user has reported.
    if (!this.post) {
      return false;
    }
    return this.reportService.hasReportedPost(this.post.id, this.currentUserId);
  }

  canDeleteComment(comment: PostComment): boolean {
    // Only the comment author or an admin may delete.
    if (!this.currentUserId) {
      return false;
    }
    if (comment.author.id === this.currentUserId) {
      return true;
    }
    return this.currentUserRole === 'ADMIN';
  }

  isCommentDeletePending(commentId: string): boolean {
    // Used to disable delete buttons while waiting for the API response.
    return this.commentDeletionState.has(commentId);
  }

  deleteComment(comment: PostComment): void {
    // Handles deletion with optimistic UI and error feedback.
    if (!this.post || !comment?.id) {
      return;
    }
    if (this.commentDeletionState.has(comment.id)) {
      return;
    }
    if (!this.canDeleteComment(comment)) {
      return;
    }
    this.commentError = '';
    this.commentDeletionState.add(comment.id);
    this.postService.deleteComment(this.post.id, comment.id).subscribe({
      next: () => {
        if (!this.post) {
          this.commentDeletionState.delete(comment.id);
          return;
        }
        const remaining = (this.post.comments ?? []).filter((item) => item.id !== comment.id);
        this.post = {
          ...this.post,
          comments: remaining,
          commentCount: Math.max(this.post.commentCount - 1, 0)
        };
        this.commentDeletionState.delete(comment.id);
      },
      error: (err) => {
        this.commentError = this.resolveErrorMessage(err, 'Unable to delete that comment right now.');
        this.commentDeletionState.delete(comment.id);
      }
    });
  }

  // Resolves the appropriate error message based on the API response.
  private resolveErrorMessage(error: unknown, fallback: string): string {
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }

  private shouldRedirectToHome(error: unknown): boolean {
    const status = (error as { status?: number })?.status;
    return status === 404 || status === 400;
  }

  private redirectToHome(): void {
    this.router.navigate(['/']);
  }
}
