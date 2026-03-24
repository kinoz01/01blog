import { CommonModule } from '@angular/common';
import { Component, HostListener, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';

import { ReportSummary } from '../../core/models/report.models';
import { AdminService } from '../../core/services/admin.service';
import { Observable, forkJoin } from 'rxjs';
import { AdminUser } from '../../core/models/admin.models';
import { Post } from '../../core/models/post.models';

@Component({
  selector: 'app-admin-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './admin-dashboard.component.html',
  styleUrl: './admin-dashboard.component.scss'
})
// Admin landing page that aggregates reports, users, and posts for moderation tasks.
export class AdminDashboardComponent implements OnInit {
  reports: ReportSummary[] = [];
  users: AdminUser[] = [];
  posts: Post[] = [];
  isLoading = false;
  error = '';
  menuContext: { type: 'user' | 'post'; id: string } | null = null;
  private readonly adminService = inject(AdminService);
  // Tracks actions (ban/hide/delete) in-flight so buttons can show spinners and avoid duplicate requests.
  private readonly actionState = new Set<string>();
  // Keeps track of reports dismissed via the UI so they can be hidden without a page refresh.
  private readonly dismissedReportIds = new Set<string>();

  ngOnInit(): void {
    // Load all admin data upfront so the dashboard has reports/users/posts ready.
    this.loadAll();
  }

  @HostListener('document:click')
  closeMenu(): void {
    // Clicking outside the action menu should close it (expected UX behavior).
    this.menuContext = null;
  }

  loadAll(showSpinner = true): void {
    if (showSpinner) {
      this.isLoading = true;
    }
    this.error = '';
    // Load reports, users, and posts concurrently so the dashboard populates in one pass.
    forkJoin({
      reports: this.adminService.getReports(),
      users: this.adminService.getUsers(),
      posts: this.adminService.getPosts()
    }).subscribe({
      next: ({ reports, users, posts }) => {
        this.reports = reports.filter((report) => !this.dismissedReportIds.has(report.id));
        this.users = users;
        this.posts = posts;
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Unable to load admin data right now.';
        this.isLoading = false;
      }
    });
  }

  isActionPending(key: string): boolean {
    // Helper for templates to disable buttons while a given action is running.
    return this.actionState.has(key);
  }

  toggleMenu(type: 'user' | 'post', id: string, event: MouseEvent): void {
    // Toggle context menu visibility for a specific user/post row.
    event.stopPropagation();
    if (this.menuContext && this.menuContext.type === type && this.menuContext.id === id) {
      this.menuContext = null;
      return;
    }
    this.menuContext = { type, id };
  }
  
  onMenuContentClick(event: MouseEvent): void {
    // Prevent clicks inside the menu from closing it.
    event.stopPropagation();
  }

  banUserById(userId: string): void {
    // Wrapper so buttons can ban a user and show loading states.
    this.runAction(`ban-${userId}`, this.adminService.banUser(userId));
  }

  unbanUserById(userId: string): void {
    // Wrapper to unban a user via the admin API.
    this.runAction(`unban-${userId}`, this.adminService.unbanUser(userId));
  }

  removeUserById(userId: string): void {
    // Prompt for confirmation since removal deletes all data.
    if (!confirm('Remove this user and all of their content? This cannot be undone.')) {
      return;
    }
    this.runAction(`remove-${userId}`, this.adminService.removeUser(userId));
  }

  hidePostById(postId: string): void {
    // Soft-hide a post so it’s no longer public.
    this.runAction(`hide-${postId}`, this.adminService.hidePost(postId));
  }

  unhidePostById(postId: string): void {
    // Make a previously hidden post visible again.
    this.runAction(`unhide-${postId}`, this.adminService.unhidePost(postId));
  }

  deletePostById(postId: string): void {
    // Hard-delete requires confirmation and prunes posts/reports locally.
    if (!confirm('Delete this post permanently? This cannot be undone.')) {
      return;
    }
    this.runAction(`delete-${postId}`, this.adminService.deletePost(postId), () => {
      this.posts = this.posts.filter((post) => post.id !== postId);
      this.reports = this.reports.filter((report) => report.reportedPost?.id !== postId);
      if (this.menuContext?.type === 'post' && this.menuContext.id === postId) {
        this.menuContext = null;
      }
    });
  }

  toggleUserBan(user: AdminUser): void {
    // Convenience helper for toggling ban state inline in the table.
    if (user.banned) {
      this.unbanUserById(user.id);
    } else {
      this.banUserById(user.id);
    }
  }

  togglePostVisibility(post: Post): void {
    // Toggles between showing/hiding a post without needing two buttons.
    if (post.hidden) {
      this.unhidePostById(post.id);
    } else {
      this.hidePostById(post.id);
    }
  }

  removeUser(report: ReportSummary): void {
    // Contextual action within the report card to remove the reported user.
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.removeUserById(userId);
  }

  banUser(report: ReportSummary): void {
    // Ban action from the report card, reusing the regular handler.
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.banUserById(userId);
  }

  unbanUser(report: ReportSummary): void {
    // Unban directly from the report card if needed.
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.unbanUserById(userId);
  }

  hidePost(report: ReportSummary): void {
    // Hide the reported post directly from the report list.
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.hidePostById(postId);
  }

  unhidePost(report: ReportSummary): void {
    // Undo a hide from the report UI without navigating away.
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.unhidePostById(postId);
  }

  deletePost(report: ReportSummary): void {
    // Permanently remove the reported post via the existing handler.
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.deletePostById(postId);
  }

  private runAction<T>(key: string, action$: Observable<T>, onSuccess?: () => void): void {
    // Centralized handler that tracks action state and reloads after success.
    if (this.actionState.has(key)) {
      return;
    }
    this.actionState.add(key);
    action$.subscribe({
      next: () => {
        onSuccess?.();
        this.actionState.delete(key);
        // Reload data without spinner so the UI reflects moderation changes immediately.
        this.loadAll(false);
      },
      error: () => {
        this.error = 'Unable to complete that action right now.';
        this.actionState.delete(key);
      }
    });
  }
}
