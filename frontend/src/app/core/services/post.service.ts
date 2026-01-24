import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Post, PostComment } from '../models/post.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class PostService {
  private readonly baseUrl = `${environment.apiUrl}/posts`;
  private readonly apiOrigin = environment.apiUrl.replace(/\/$/, '').replace(/\/api$/, '');

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  getFeed(): Observable<Post[]> {
    return this.http.get<Post[]>(this.baseUrl, { headers: this.authService.buildAuthHeaders() }).pipe(
      map((posts) => posts.map((post) => this.normalizePost(post)))
    );
  }

  getPost(id: string): Observable<Post> {
    return this.http
      .get<Post>(`${this.baseUrl}/${id}`, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((post) => this.normalizePost(post)));
  }

  createPost(payload: { title: string; description: string; media: File[] }): Observable<Post> {
    const formData = new FormData();
    formData.append('title', payload.title);
    formData.append('description', payload.description);
    payload.media.forEach((file) => formData.append('media', file));

    return this.http
      .post<Post>(this.baseUrl, formData, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((post) => this.normalizePost(post)));
  }

  updatePost(
    id: string,
    payload: { title: string; description: string; removeMediaIds?: string[]; media?: File[] }
  ): Observable<Post> {
    const formData = new FormData();
    const request = {
      title: payload.title,
      description: payload.description,
      removeMediaIds: payload.removeMediaIds ?? []
    };
    formData.append('request', new Blob([JSON.stringify(request)], { type: 'application/json' }));
    (payload.media ?? []).forEach((file) => formData.append('media', file));

    return this.http
      .put<Post>(`${this.baseUrl}/${id}`, formData, {
        headers: this.authService.buildAuthHeaders()
      })
      .pipe(map((post) => this.normalizePost(post)));
  }

  deletePost(id: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, {
      headers: this.authService.buildAuthHeaders()
    });
  }

  likePost(id: string): Observable<Post> {
    return this.http
      .post<Post>(`${this.baseUrl}/${id}/likes`, {}, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((post) => this.normalizePost(post)));
  }

  unlikePost(id: string): Observable<Post> {
    return this.http
      .delete<Post>(`${this.baseUrl}/${id}/likes`, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((post) => this.normalizePost(post)));
  }

  addComment(postId: string, content: string): Observable<PostComment> {
    return this.http.post<PostComment>(
      `${this.baseUrl}/${postId}/comments`,
      { content },
      { headers: this.authService.buildAuthHeaders() }
    );
  }

  private normalizePost(post: Post): Post {
    const media = (post.media ?? []).map((item) => ({
      ...item,
      url: item.url?.startsWith('http') ? item.url : `${this.apiOrigin}${item.url}`
    }));
    const comments = post.comments ? [...post.comments] : undefined;
    return { ...post, media, comments };
  }
}
