export interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: 'USER' | 'ADMIN';
  createdAt: string;
  updatedAt: string;
  banned: boolean;
  postCount: number;
}
