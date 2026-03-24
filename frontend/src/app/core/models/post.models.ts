// Media types supported by posts.
export type MediaKind = 'IMAGE' | 'VIDEO';

// Metadata for a single media attachment on a post.
export interface PostMedia {
  id: string;
  url: string;
  mimeType: string;
  type: MediaKind;
  originalFileName?: string;
}

// Lightweight user info bundled with posts/comments.
export interface AuthorSummary {
  id: string;
  name: string;
  role: 'USER' | 'ADMIN';
}

// Comment entity rendered beneath posts.
export interface PostComment {
  id: string;
  content: string;
  createdAt: string;
  updatedAt: string;
  author: AuthorSummary;
}

// Main post model consumed throughout the UI.
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
