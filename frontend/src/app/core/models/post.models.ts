export type MediaKind = 'IMAGE' | 'VIDEO';

export interface PostMedia {
  id: string;
  url: string;
  mimeType: string;
  type: MediaKind;
  originalFileName?: string;
}

export interface AuthorSummary {
  id: string;
  name: string;
  role: 'USER' | 'ADMIN';
}

export interface PostComment {
  id: string;
  content: string;
  createdAt: string;
  updatedAt: string;
  author: AuthorSummary;
}

export interface Post {
  id: string;
  title: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  author: AuthorSummary;
  media: PostMedia[];
  likeCount: number;
  commentCount: number;
  likedByCurrentUser: boolean;
  comments?: PostComment[];
  hidden: boolean;
}
