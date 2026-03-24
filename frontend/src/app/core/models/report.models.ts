// Types of entities that can be reported.
export type ReportTargetType = 'USER' | 'POST';
// Workflow states for a report.
export type ReportStatus = 'OPEN' | 'RESOLVED';

// Full report payload shown in the admin moderation queue.
export interface ReportSummary {
  id: string;
  targetType: ReportTargetType;
  status: ReportStatus;
  reason: string;
  createdAt: string;
  resolvedAt?: string;
  reporter: {
    id: string;
    name: string;
    email: string;
  };
  reportedUser?: {
    id: string;
    name: string;
    email: string;
    banned: boolean;
  };
  reportedPost?: {
    id: string;
    title: string;
    hidden: boolean;
    authorId?: string;
    authorName?: string;
  };
}
