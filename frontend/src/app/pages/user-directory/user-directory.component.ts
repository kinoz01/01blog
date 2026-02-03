import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';

import { UserSummary } from '../../core/models/user.models';
import { UserService } from '../../core/services/user.service';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-user-directory',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './user-directory.component.html',
  styleUrl: './user-directory.component.scss'
})
export class UserDirectoryComponent implements OnDestroy, OnInit {
  users: UserSummary[] = [];
  filtered: UserSummary[] = [];
  search = '';
  isLoading = true;
  error = '';
  hasSearched = false;
  private currentUserId: string | null = null;

  private readonly userService = inject(UserService);
  private readonly authService = inject(AuthService);
  private readonly destroy$ = new Subject<void>();

  ngOnInit(): void {
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.applyFilter();
    });
    this.userService
      .getDirectory()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (users) => {
          this.users = users;
          this.applyFilter();
          this.isLoading = false;
        },
        error: (err) => {
          this.error =
            typeof err === 'string' ? err : err?.error?.message ?? 'Unable to load the directory right now.';
          this.isLoading = false;
        }
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  trackByUser(_index: number, user: UserSummary): string {
    return user.id;
  }

  onSearch(term: string): void {
    this.search = term;
    this.hasSearched = true;
    this.applyFilter();
  }

  private applyFilter(): void {
    const normalized = this.search.trim().toLowerCase();
    const visibleUsers = this.excludeCurrentUser(this.users);
    if (!this.hasSearched) {
      this.filtered = visibleUsers;
      return;
    }
    if (!normalized) {
      this.filtered = [];
      return;
    }
    this.filtered = visibleUsers.filter((user) => user.name.toLowerCase().includes(normalized));
  }

  private excludeCurrentUser(users: UserSummary[]): UserSummary[] {
    if (!this.currentUserId) {
      return users;
    }
    return users.filter((user) => user.id !== this.currentUserId);
  }
}
