import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Notification } from '../models/notification.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class NotificationService {
  private readonly baseUrl = `${environment.apiUrl}/notifications`;

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  list(): Observable<Notification[]> {
    return this.http.get<Notification[]>(this.baseUrl, { headers: this.authService.buildAuthHeaders() });
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }
}
