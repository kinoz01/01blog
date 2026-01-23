export interface Notification {
  id: string;
  type: 'POST_PUBLISHED';
  actorId: string;
  actorName: string;
  postId: string;
  message: string;
  createdAt: string;
  readAt: string | null;
}
