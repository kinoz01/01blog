import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, of, switchMap, takeUntil, catchError } from 'rxjs';

import { Post } from '../../core/models/post.models';
import { PostService } from '../../core/services/post.service';

@Component({
  selector: 'app-post-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './post-detail.component.html',
  styleUrl: './post-detail.component.scss'
})
export class PostDetailComponent implements OnDestroy, OnInit {
  post: Post | null = null;
  isLoading = true;
  error = '';

  private readonly route = inject(ActivatedRoute);
  private readonly postService = inject(PostService);
  private readonly destroy$ = new Subject<void>();

  ngOnInit(): void {
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
        this.post = post;
        this.isLoading = false;
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
}
