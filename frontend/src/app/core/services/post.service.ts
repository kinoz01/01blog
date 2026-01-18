import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';

import { environment } from '../../../environments/environment';
import { Post } from '../models/post.models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class PostService {
  private readonly baseUrl = `${environment.apiUrl}/posts`;
  private readonly apiOrigin = environment.apiUrl.replace(/\/$/, '').replace(/\/api$/, '');

  constructor(private readonly http: HttpClient, private readonly authService: AuthService) {}

  getFeed(): Observable<Post[]> {
    return this.http.get<Post[]>(this.baseUrl, { headers: this.authService.buildAuthHeaders() }).pipe(
      map((posts) => posts.map((post) => this.normalizeMedia(post)))
    );
  }

  createPost(payload: { title: string; description: string; media: File[] }): Observable<Post> {
    const formData = new FormData();
    formData.append('title', payload.title);
    formData.append('description', payload.description);
    payload.media.forEach((file) => formData.append('media', file));

    return this.http
      .post<Post>(this.baseUrl, formData, { headers: this.authService.buildAuthHeaders() })
      .pipe(map((post) => this.normalizeMedia(post)));
  }

  private normalizeMedia(post: Post): Post {
    if (!post.media?.length) {
      return post;
    }
    const media = post.media.map((item) => ({
      ...item,
      url: item.url.startsWith('http') ? item.url : `${this.apiOrigin}${item.url}`
    }));
    return { ...post, media };
  }
}
