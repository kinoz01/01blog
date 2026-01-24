import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class ReportService {
  private readonly baseUrl = environment.apiUrl;

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  reportUser(userId: string, reason: string): Observable<void> {
    return this.http.post<void>(
      `${this.baseUrl}/users/${userId}/report`,
      { reason },
      { headers: this.authService.buildAuthHeaders() }
    );
  }

  reportPost(postId: string, reason: string): Observable<void> {
    return this.http.post<void>(
      `${this.baseUrl}/posts/${postId}/report`,
      { reason },
      { headers: this.authService.buildAuthHeaders() }
    );
  }
}
