import { Post } from './post.models';

export interface UserProfileDetails {
  id: string;
  name: string;
  role: 'USER' | 'ADMIN';
  createdAt: string;
  updatedAt: string;
  postCount: number;
  posts: Post[];
  subscribed: boolean;
}

export interface UserSummary {
  id: string;
  name: string;
}
