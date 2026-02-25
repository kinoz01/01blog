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
export class NotificationsComponent implements OnDestroy, OnInit {
  notifications: Notification[] = [];
  isLoading = true;
  error = '';
  deleting: Record<string, boolean> = {};

  private readonly notificationService = inject(NotificationService);
  private readonly destroy$ = new Subject<void>();

  ngOnInit(): void {
    this.refresh();
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

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

  trackByNotification(_index: number, item: Notification): string {
    return item.id;
  }
}
