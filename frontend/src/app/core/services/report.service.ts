import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, tap } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth.service';

interface StoredReportedTargets {
  [userId: string]: {
    posts?: string[];
    users?: string[];
  };
}

interface ReportedCache {
  posts: Set<string>;
  users: Set<string>;
}

@Injectable({ providedIn: 'root' })
// Handles reporting actions and caches which targets a user already reported.
export class ReportService {
  private readonly baseUrl = environment.apiUrl;
  private readonly storageKey = 'maaref-reported-targets';
  private readonly reportedTargets = new Map<string, ReportedCache>();

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {
    this.restoreReportedTargets();
  }

  // Submits a report against a user and updates local cache.
  reportUser(userId: string, reason: string, reporterId: string | null): Observable<void> {
    return this.http
      .post<void>(
        `${this.baseUrl}/users/${userId}/report`,
        { reason },
        { headers: this.authService.buildAuthHeaders() }
      )
      .pipe(tap(() => this.markUserReported(userId, reporterId)));
  }

  // Submits a report against a post and updates local cache.
  reportPost(postId: string, reason: string, reporterId: string | null): Observable<void> {
    return this.http
      .post<void>(
        `${this.baseUrl}/posts/${postId}/report`,
        { reason },
        { headers: this.authService.buildAuthHeaders() }
      )
      .pipe(tap(() => this.markPostReported(postId, reporterId)));
  }

  // Checks if the given user has already reported the specified post.
  hasReportedPost(postId: string, reporterId: string | null): boolean {
    if (!reporterId || !postId) {
      return false;
    }
    return this.reportedTargets.get(reporterId)?.posts.has(postId) ?? false;
  }

  // Checks if the given user has already reported the specified user.
  hasReportedUser(userId: string, reporterId: string | null): boolean {
    if (!reporterId || !userId) {
      return false;
    }
    return this.reportedTargets.get(reporterId)?.users.has(userId) ?? false;
  }

  // Marks a post as reported locally so we can disable the button client-side.
  private markPostReported(postId: string, reporterId: string | null): void {
    if (!postId || !reporterId) {
      return;
    }
    const cache = this.ensureCache(reporterId);
    cache.posts.add(postId);
    this.persistReportedTargets();
  }

  // Marks a user as reported locally.
  private markUserReported(userId: string, reporterId: string | null): void {
    if (!userId || !reporterId) {
      return;
    }
    const cache = this.ensureCache(reporterId);
    cache.users.add(userId);
    this.persistReportedTargets();
  }

  // Ensures we have a Set cache for the provided user id.
  private ensureCache(userId: string): ReportedCache {
    if (!this.reportedTargets.has(userId)) {
      this.reportedTargets.set(userId, { posts: new Set(), users: new Set() });
    }
    return this.reportedTargets.get(userId)!;
  }

  // Restores cached reported targets from localStorage during service init.
  private restoreReportedTargets(): void {
    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    try {
      const raw = storage.getItem(this.storageKey);
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw) as StoredReportedTargets;
      this.reportedTargets.clear();
      Object.entries(parsed).forEach(([userId, targets]) => {
        this.reportedTargets.set(userId, {
          posts: new Set(targets.posts ?? []),
          users: new Set(targets.users ?? [])
        });
      });
    } catch {
      this.reportedTargets.clear();
    }
  }

  // Persists the current reported target cache to localStorage.
  private persistReportedTargets(): void {
    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    try {
      const payload: StoredReportedTargets = {};
      this.reportedTargets.forEach((cache, userId) => {
        payload[userId] = {
          posts: Array.from(cache.posts),
          users: Array.from(cache.users)
        };
      });
      storage.setItem(this.storageKey, JSON.stringify(payload));
    } catch {
      /* no-op */
    }
  }

  // Guarded access to window.localStorage (no-op during SSR).
  private getStorage(): Storage | null {
    if (typeof window === 'undefined') {
      return null;
    }
    try {
      return window.localStorage;
    } catch {
      return null;
    }
  }
}
