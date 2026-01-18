import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, map, tap } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthResponse, AuthState, LoginPayload, RegisterPayload, UserProfile } from '../models/auth.models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly storageKey = 'blog-auth';
  private readonly authUrl = `${environment.apiUrl}/auth`;

  private readonly stateSubject = new BehaviorSubject<AuthState | null>(null);
  readonly state$ = this.stateSubject.asObservable();
  readonly user$ = this.state$.pipe(map((state) => state?.user ?? null));
  readonly isAuthenticated$ = this.state$.pipe(map((state) => !!state?.token));

  constructor(private readonly http: HttpClient) {
    this.restoreSession();
  }

  login(payload: LoginPayload): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.authUrl}/login`, payload).pipe(tap((response) => this.persist(response)));
  }

  register(payload: RegisterPayload): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.authUrl}/register`, payload).pipe(tap((response) => this.persist(response)));
  }

  me(): Observable<UserProfile> {
    return this.http
      .get<UserProfile>(`${this.authUrl}/me`, { headers: this.buildAuthHeaders() })
      .pipe(tap((profile) => this.patchUser(profile)));
  }

  logout(): void {
    this.stateSubject.next(null);
    localStorage.removeItem(this.storageKey);
  }

  get token(): string | null {
    return this.stateSubject.value?.token ?? null;
  }

  private persist(response: AuthResponse): void {
    const expiresAt = Date.now() + response.expiresIn;
    const state: AuthState = {
      token: response.token,
      expiresAt,
      user: response.user ?? null
    };
    this.stateSubject.next(state);
    localStorage.setItem(this.storageKey, JSON.stringify(state));
  }

  private patchUser(user: UserProfile): void {
    const current = this.stateSubject.value;
    if (!current) {
      return;
    }
    const updated: AuthState = { ...current, user };
    this.stateSubject.next(updated);
    localStorage.setItem(this.storageKey, JSON.stringify(updated));
  }

  private restoreSession(): void {
    const raw = localStorage.getItem(this.storageKey);
    if (!raw) {
      return;
    }
    try {
      const parsed = JSON.parse(raw) as AuthState;
      if (parsed.expiresAt > Date.now()) {
        this.stateSubject.next(parsed);
      } else {
        localStorage.removeItem(this.storageKey);
      }
    } catch (error) {
      localStorage.removeItem(this.storageKey);
    }
  }

  buildAuthHeaders(additional: Record<string, string> = {}): HttpHeaders {
    const token = this.token;
    const headers: Record<string, string> = { ...additional };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return new HttpHeaders(headers);
  }
}
