import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, map, tap } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthResponse, AuthState, LoginPayload, RegisterPayload, UserProfile } from '../models/auth.models';

@Injectable({ providedIn: 'root' })
// Central auth service handling login, registration, profile lookups, and token storage.
export class AuthService {
  private readonly storageKey = 'maaref-auth';
  private readonly authUrl = `${environment.apiUrl}/auth`;

  private readonly stateSubject = new BehaviorSubject<AuthState | null>(null);
  // Observable that consumers subscribe to for auth state changes.
  readonly state$ = this.stateSubject.asObservable();
  // Derived observable exposing just the user profile (or null).
  readonly user$ = this.state$.pipe(map((state) => state?.user ?? null));
  // Emits true when a token exists, false otherwise.
  readonly isAuthenticated$ = this.state$.pipe(map((state) => !!state?.token));

  constructor(private readonly http: HttpClient) {
    this.restoreSession();
  }

  // Sends credentials to the login endpoint and persists the returned session.
  login(payload: LoginPayload): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.authUrl}/login`, payload).pipe(tap((response) => this.persist(response)));
  }

  // Registers a new user and immediately stores the returned session.
  register(payload: RegisterPayload): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.authUrl}/register`, payload).pipe(tap((response) => this.persist(response)));
  }

  // Calls /auth/me to retrieve the authenticated user's profile and cache it.
  me(): Observable<UserProfile> {
    return this.http
      .get<UserProfile>(`${this.authUrl}/me`, { headers: this.buildAuthHeaders() })
      .pipe(tap((profile) => this.patchUser(profile)));
  }

  // Clears the in-memory and persisted session.
  logout(): void {
    this.stateSubject.next(null);
    localStorage.removeItem(this.storageKey);
  }

  // Shortcut to the raw token, used for header construction.
  get token(): string | null {
    return this.stateSubject.value?.token ?? null;
  }

  // Persists the auth response with an absolute expiration timestamp.
  private persist(response: AuthResponse): void {
    const expiresAt = Date.now() + response.expiresIn;
    const state: AuthState = {
      token: response.token,
      expiresAt,
      user: response.user ?? null,
      profileValidated: true
    };
    this.stateSubject.next(state);
    localStorage.setItem(this.storageKey, JSON.stringify(state));
  }

  // Updates the cached user object while retaining the existing token info.
  private patchUser(user: UserProfile): void {
    const current = this.stateSubject.value;
    if (!current) {
      return;
    }
    const updated: AuthState = { ...current, user, profileValidated: true };
    this.stateSubject.next(updated);
    localStorage.setItem(this.storageKey, JSON.stringify(updated));
  }

  // Restores session state from localStorage on app boot, validating expiry.
  private restoreSession(): void {
    const raw = localStorage.getItem(this.storageKey);
    if (!raw) {
      return;
    }
    try {
      const parsed = JSON.parse(raw) as AuthState;
      if (parsed.expiresAt > Date.now()) {
        const restored: AuthState = {
          token: parsed.token,
          expiresAt: parsed.expiresAt,
          user: parsed.user ?? null,
          profileValidated: false
        };
        this.stateSubject.next(restored);
      } else {
        localStorage.removeItem(this.storageKey);
      }
    } catch (error) {
      localStorage.removeItem(this.storageKey);
    }
  }

  // Utility for building Authorization headers for protected API calls.
  buildAuthHeaders(additional: Record<string, string> = {}): HttpHeaders {
    const token = this.token;
    const headers: Record<string, string> = { ...additional };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return new HttpHeaders(headers);
  }
}
