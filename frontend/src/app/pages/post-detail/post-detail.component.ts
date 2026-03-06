import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, of, switchMap, takeUntil, catchError } from 'rxjs';

import { Post } from '../../core/models/post.models';
import { PostService } from '../../core/services/post.service';
import { AuthService } from '../../core/services/auth.service';
import { ReportService } from '../../core/services/report.service';

@Component({
  selector: 'app-post-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, ReactiveFormsModule],
  templateUrl: './post-detail.component.html',
  styleUrl: './post-detail.component.scss'
})
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

  private readonly route = inject(ActivatedRoute);
  private readonly postService = inject(PostService);
  private readonly authService = inject(AuthService);
  private readonly reportService = inject(ReportService);
  private readonly fb = inject(FormBuilder);
  private readonly destroy$ = new Subject<void>();

  readonly commentForm = this.fb.nonNullable.group({
    content: ['', [Validators.required, Validators.maxLength(this.commentMaxLength)]]
  });

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
            this.error = 'We could not find that post.';
            this.isLoading = false;
            return of(null);
          }
          this.isLoading = true;
          this.error = '';
          return this.postService.getPost(postId).pipe(
            catchError((err) => {
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
    if (this.isOwner()) {
      return;
    }
    this.reportForm.reset();
    this.reportModalOpen = true;
    this.reportError = '';
  }

  closeReportModal(): void {
    this.reportModalOpen = false;
    this.reportForm.reset();
    this.reportSubmitting = false;
    this.reportError = '';
  }

  submitReport(): void {
    if (!this.post) {
      return;
    }
    if (this.reportForm.invalid) {
      this.reportForm.markAllAsTouched();
      return;
    }
    this.reportSubmitting = true;
    this.reportError = '';
    const reason = this.reportForm.controls.reason.value ?? '';
    this.reportService.reportPost(this.post.id, reason).subscribe({
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

  canReportPost(): boolean {
    if (!this.post || this.isOwner()) {
      return false;
    }
    if (this.currentUserRole === 'ADMIN') {
      return false;
    }
    return this.post.author.role !== 'ADMIN';
  }

  private resolveErrorMessage(error: unknown, fallback: string): string {
    if (typeof error === 'string') {
      return error;
    }
    const apiMessage = (error as { error?: { message?: string } })?.error?.message;
    return apiMessage ?? fallback;
  }
}
