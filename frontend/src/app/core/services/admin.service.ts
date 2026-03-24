import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Post } from '../models/post.models';
import { ReportSummary } from '../models/report.models';
import { AdminUser } from '../models/admin.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' }) // injectable means this service can be injected into components and other services
// Client-side gateway for moderation endpoints under /api/admin.
export class AdminService {
  private readonly baseUrl = `${environment.apiUrl}/admin`;

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  // Fetches the full report queue for the admin dashboard.
  getReports(): Observable<ReportSummary[]> {
    return this.http.get<ReportSummary[]>(`${this.baseUrl}/reports`, {
      headers: this.authService.buildAuthHeaders()
    });
  }
  
  // Returns all registered users with moderation metadata.
  getUsers(): Observable<AdminUser[]> {
    return this.http.get<AdminUser[]>(`${this.baseUrl}/users`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Fetches every post (including hidden ones) for review.
  getPosts(): Observable<Post[]> {
    return this.http.get<Post[]>(`${this.baseUrl}/posts`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Applies a ban to the specified user.
  banUser(userId: string): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/users/${userId}/ban`, {}, { headers: this.authService.buildAuthHeaders() });
  }

  // Removes an existing ban.
  unbanUser(userId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/users/${userId}/ban`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Permanently deletes a user account and related data.
  removeUser(userId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/users/${userId}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Marks a post as hidden.
  hidePost(postId: string): Observable<Post> {
    return this.http.post<Post>(`${this.baseUrl}/posts/${postId}/hide`, {}, { headers: this.authService.buildAuthHeaders() });
  }

  // Reverses a post hide operation.
  unhidePost(postId: string): Observable<Post> {
    return this.http.delete<Post>(`${this.baseUrl}/posts/${postId}/hide`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Permanently deletes a post.
  deletePost(postId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/posts/${postId}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }
}
