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
export class ReportService {
  private readonly baseUrl = environment.apiUrl;
  private readonly storageKey = 'maaref-reported-targets';
  private readonly reportedTargets = new Map<string, ReportedCache>();

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {
    this.restoreReportedTargets();
  }

  reportUser(userId: string, reason: string, reporterId: string | null): Observable<void> {
    return this.http
      .post<void>(
        `${this.baseUrl}/users/${userId}/report`,
        { reason },
        { headers: this.authService.buildAuthHeaders() }
      )
      .pipe(tap(() => this.markUserReported(userId, reporterId)));
  }

  reportPost(postId: string, reason: string, reporterId: string | null): Observable<void> {
    return this.http
      .post<void>(
        `${this.baseUrl}/posts/${postId}/report`,
        { reason },
        { headers: this.authService.buildAuthHeaders() }
      )
      .pipe(tap(() => this.markPostReported(postId, reporterId)));
  }

  hasReportedPost(postId: string, reporterId: string | null): boolean {
    if (!reporterId || !postId) {
      return false;
    }
    return this.reportedTargets.get(reporterId)?.posts.has(postId) ?? false;
  }

  hasReportedUser(userId: string, reporterId: string | null): boolean {
    if (!reporterId || !userId) {
      return false;
    }
    return this.reportedTargets.get(reporterId)?.users.has(userId) ?? false;
  }

  private markPostReported(postId: string, reporterId: string | null): void {
    if (!postId || !reporterId) {
      return;
    }
    const cache = this.ensureCache(reporterId);
    cache.posts.add(postId);
    this.persistReportedTargets();
  }

  private markUserReported(userId: string, reporterId: string | null): void {
    if (!userId || !reporterId) {
      return;
    }
    const cache = this.ensureCache(reporterId);
    cache.users.add(userId);
    this.persistReportedTargets();
  }

  private ensureCache(userId: string): ReportedCache {
    if (!this.reportedTargets.has(userId)) {
      this.reportedTargets.set(userId, { posts: new Set(), users: new Set() });
    }
    return this.reportedTargets.get(userId)!;
  }

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
