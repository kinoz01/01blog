import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';

import { Notification } from '../../core/models/notification.models';
import { NotificationService } from '../../core/services/notification.service';

@Component({
  selector: 'app-notifications',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './notifications.component.html',
  styleUrl: './notifications.component.scss'
})
// Simple notification center allowing users to view and dismiss their alerts.
export class NotificationsComponent implements OnDestroy, OnInit {
  notifications: Notification[] = [];
  isLoading = true;
  error = '';
  deleting: Record<string, boolean> = {};

  private readonly notificationService = inject(NotificationService);
  private readonly destroy$ = new Subject<void>();

  ngOnInit(): void {
    // Fetch notifications as soon as the component mounts.
    this.refresh();
  }

  ngOnDestroy(): void {
    // Complete the notifier to avoid leaking the refresh subscription.
    this.destroy$.next();
    this.destroy$.complete();
  }

  // Reloads the list and updates loading/error state so the template can react.
  refresh(): void {
    this.isLoading = true;
    this.error = '';
    this.notificationService
      .list()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (items) => {
          this.notifications = items;
          this.isLoading = false;
        },
        error: (err) => {
          this.error =
            typeof err === 'string' ? err : err?.error?.message ?? 'Unable to load notifications right now.';
          this.isLoading = false;
        }
      });
  }

  // Dismisses a notification locally after confirming the backend deletion succeeded.
  dismiss(notification: Notification): void {
    if (this.deleting[notification.id]) {
      return;
    }
    this.deleting[notification.id] = true;
    this.notificationService.delete(notification.id).subscribe({
      next: () => {
        this.notifications = this.notifications.filter((item) => item.id !== notification.id);
        delete this.deleting[notification.id];
      },
      error: (err) => {
        this.error =
          typeof err === 'string' ? err : err?.error?.message ?? 'Unable to dismiss that notification right now.';
        delete this.deleting[notification.id];
      }
    });
  }

  // trackBy to avoid rerendering list items unnecessarily.
  trackByNotification(_index: number, item: Notification): string {
    return item.id;
  }
}
