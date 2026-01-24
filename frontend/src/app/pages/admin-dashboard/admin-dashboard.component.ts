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
export class AdminDashboardComponent implements OnInit {
  reports: ReportSummary[] = [];
  users: AdminUser[] = [];
  posts: Post[] = [];
  isLoading = false;
  error = '';
  menuContext: { type: 'user' | 'post'; id: string } | null = null;
  private readonly adminService = inject(AdminService);
  private readonly actionState = new Set<string>();

  ngOnInit(): void {
    this.loadAll();
  }

  @HostListener('document:click')
  closeMenu(): void {
    this.menuContext = null;
  }

  loadAll(showSpinner = true): void {
    if (showSpinner) {
      this.isLoading = true;
    }
    this.error = '';
    forkJoin({
      reports: this.adminService.getReports(),
      users: this.adminService.getUsers(),
      posts: this.adminService.getPosts()
    }).subscribe({
      next: ({ reports, users, posts }) => {
        this.reports = reports;
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
    return this.actionState.has(key);
  }

  toggleMenu(type: 'user' | 'post', id: string, event: MouseEvent): void {
    event.stopPropagation();
    if (this.menuContext && this.menuContext.type === type && this.menuContext.id === id) {
      this.menuContext = null;
      return;
    }
    this.menuContext = { type, id };
  }
  
  onMenuContentClick(event: MouseEvent): void {
    event.stopPropagation();
  }

  resolve(report: ReportSummary): void {
    this.runAction(`resolve-${report.id}`, this.adminService.resolveReport(report.id));
  }

  banUserById(userId: string): void {
    this.runAction(`ban-${userId}`, this.adminService.banUser(userId));
  }

  unbanUserById(userId: string): void {
    this.runAction(`unban-${userId}`, this.adminService.unbanUser(userId));
  }

  removeUserById(userId: string): void {
    if (!confirm('Remove this user and all of their content? This cannot be undone.')) {
      return;
    }
    this.runAction(`remove-${userId}`, this.adminService.removeUser(userId));
  }

  hidePostById(postId: string): void {
    this.runAction(`hide-${postId}`, this.adminService.hidePost(postId));
  }

  unhidePostById(postId: string): void {
    this.runAction(`unhide-${postId}`, this.adminService.unhidePost(postId));
  }

  deletePostById(postId: string): void {
    if (!confirm('Delete this post permanently? This cannot be undone.')) {
      return;
    }
    this.runAction(`delete-${postId}`, this.adminService.deletePost(postId));
  }

  toggleUserBan(user: AdminUser): void {
    if (user.banned) {
      this.unbanUserById(user.id);
    } else {
      this.banUserById(user.id);
    }
  }

  togglePostVisibility(post: Post): void {
    if (post.hidden) {
      this.unhidePostById(post.id);
    } else {
      this.hidePostById(post.id);
    }
  }

  removeUser(report: ReportSummary): void {
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.removeUserById(userId);
  }

  banUser(report: ReportSummary): void {
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.banUserById(userId);
  }

  unbanUser(report: ReportSummary): void {
    const userId = report.reportedUser?.id;
    if (!userId) {
      return;
    }
    this.unbanUserById(userId);
  }

  hidePost(report: ReportSummary): void {
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.hidePostById(postId);
  }

  unhidePost(report: ReportSummary): void {
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.unhidePostById(postId);
  }

  deletePost(report: ReportSummary): void {
    const postId = report.reportedPost?.id;
    if (!postId) {
      return;
    }
    this.deletePostById(postId);
  }

  private runAction<T>(key: string, action$: Observable<T>): void {
    if (this.actionState.has(key)) {
      return;
    }
    this.actionState.add(key);
    action$.subscribe({
      next: () => {
        this.actionState.delete(key);
        this.loadAll(false);
      },
      error: () => {
        this.error = 'Unable to complete that action right now.';
        this.actionState.delete(key);
      }
    });
  }
}
