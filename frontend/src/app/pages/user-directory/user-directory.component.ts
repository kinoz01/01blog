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
// Page that lists users with a client-side search box.
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
    // Watch auth changes so we can filter out the current user from the directory.
    this.authService.user$.pipe(takeUntil(this.destroy$)).subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.applyFilter();
    });
    // Load the user directory once and persist the list locally.
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
    // Complete subscriptions when the component is destroyed.
    this.destroy$.next();
    this.destroy$.complete();
  }

  trackByUser(_index: number, user: UserSummary): string {
    // trackBy function for better ngFor performance.
    return user.id;
  }

  onSearch(term: string): void {
    // Update the search term and re-run the filter whenever the user types.
    this.search = term;
    this.hasSearched = true;
    this.applyFilter();
  }

  private applyFilter(): void {
    // Filter results against the search term while hiding the current user entry.
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
    // Prevents the directory from showing the logged-in user (reduces UI clutter).
    if (!this.currentUserId) {
      return users;
    }
    return users.filter((user) => user.id !== this.currentUserId);
  }
}
