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
}

export interface Post {
  id: string;
  title: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  author: AuthorSummary;
  media: PostMedia[];
}
