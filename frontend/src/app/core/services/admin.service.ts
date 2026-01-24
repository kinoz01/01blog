import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Post } from '../models/post.models';
import { ReportSummary } from '../models/report.models';
import { AdminUser } from '../models/admin.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class AdminService {
  private readonly baseUrl = `${environment.apiUrl}/admin`;

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  getReports(): Observable<ReportSummary[]> {
    return this.http.get<ReportSummary[]>(`${this.baseUrl}/reports`, {
      headers: this.authService.buildAuthHeaders()
    });
  }
  
  getUsers(): Observable<AdminUser[]> {
    return this.http.get<AdminUser[]>(`${this.baseUrl}/users`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  getPosts(): Observable<Post[]> {
    return this.http.get<Post[]>(`${this.baseUrl}/posts`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  resolveReport(reportId: string): Observable<ReportSummary> {
    return this.http.post<ReportSummary>(
      `${this.baseUrl}/reports/${reportId}/resolve`,
      {},
      { headers: this.authService.buildAuthHeaders() }
    );
  }

  banUser(userId: string): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/users/${userId}/ban`, {}, { headers: this.authService.buildAuthHeaders() });
  }

  unbanUser(userId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/users/${userId}/ban`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  removeUser(userId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/users/${userId}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  hidePost(postId: string): Observable<Post> {
    return this.http.post<Post>(`${this.baseUrl}/posts/${postId}/hide`, {}, { headers: this.authService.buildAuthHeaders() });
  }

  unhidePost(postId: string): Observable<Post> {
    return this.http.delete<Post>(`${this.baseUrl}/posts/${postId}/hide`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  deletePost(postId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/posts/${postId}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }
}
