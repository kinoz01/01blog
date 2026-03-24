import { Post } from './post.models';

// Detailed profile view returned from /users/:id/profile.
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

// Minimal user document used for directories/autocomplete.
export interface UserSummary {
  id: string;
  name: string;
}
