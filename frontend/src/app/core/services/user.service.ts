import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Post } from '../models/post.models';
import { UserProfileDetails, UserSummary } from '../models/user.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
// Client-side service for user profile data and subscription actions.
export class UserService {
  private readonly baseUrl = `${environment.apiUrl}/users`;
  private readonly apiOrigin = environment.apiUrl.replace(/\/$/, '').replace(/\/api$/, '');

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  // Retrieves a full user profile so profile pages can render posts + stats.
  getProfile(userId: string): Observable<UserProfileDetails> {
    return this.http
      .get<UserProfileDetails>(`${this.baseUrl}/${userId}/profile`, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((profile) => this.normalizeProfile(profile)));
  }

  // Subscribes to another user so our feed can include their posts.
  subscribe(userId: string): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/${userId}/subscribe`, {}, { headers: this.authService.buildAuthHeaders() });
  }

  // Removes a subscription when the user opts out.
  unsubscribe(userId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${userId}/subscribe`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Fetches a lightweight directory for search/autocomplete features.
  getDirectory(): Observable<UserSummary[]> {
    return this.http.get<UserSummary[]>(`${this.baseUrl}/directory`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  // Normalizes profile posts so downstream components get absolute media URLs.
  private normalizeProfile(profile: UserProfileDetails): UserProfileDetails {
    const posts = (profile.posts ?? []).map((post) => this.normalizePost(post));
    return { ...profile, posts };
  }

  // Ensures each post's media array has absolute URLs (the API returns relative paths).
  private normalizePost(post: Post): Post {
    const media = (post.media ?? []).map((item) => ({
      ...item,
      url: item.url.startsWith('http') ? item.url : `${this.apiOrigin}${item.url}`
    }));
    return { ...post, media };
  }
}
