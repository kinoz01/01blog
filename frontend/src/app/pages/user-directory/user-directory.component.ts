import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';

import { UserSummary } from '../../core/models/user.models';
import { UserService } from '../../core/services/user.service';

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

  private readonly userService = inject(UserService);
  private readonly destroy$ = new Subject<void>();

  ngOnInit(): void {
    this.userService
      .getDirectory()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (users) => {
          this.users = users;
          this.filtered = users;
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
    const normalized = term.trim().toLowerCase();
    if (!normalized) {
      this.filtered = [];
      return;
    }
    this.filtered = this.users.filter((user) => user.name.toLowerCase().includes(normalized));
  }
}
