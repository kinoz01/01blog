import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export type ConfirmationTone = 'primary' | 'danger';

export interface ConfirmationOptions {
  title?: string;
  message: string;
  description?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: ConfirmationTone;
}

export interface ConfirmationDialogState {
  title: string;
  message: string;
  description?: string;
  confirmLabel: string;
  cancelLabel: string;
  tone: ConfirmationTone;
}

@Injectable({ providedIn: 'root' })
export class ConfirmationService {
  private readonly stateSubject = new BehaviorSubject<ConfirmationDialogState | null>(null);
  private resolver: ((result: boolean) => void) | null = null;

  get state$(): Observable<ConfirmationDialogState | null> {
    return this.stateSubject.asObservable();
  }

  confirm(options: ConfirmationOptions): Promise<boolean> {
    const defaults: ConfirmationDialogState = {
      title: 'Please confirm',
      message: '',
      confirmLabel: 'Confirm',
      cancelLabel: 'Cancel',
      tone: 'primary'
    };

    if (this.resolver) {
      this.resolve(false);
    }

    const dialogState: ConfirmationDialogState = {
      ...defaults,
      ...options,
      title: options.title ?? defaults.title,
      confirmLabel: options.confirmLabel ?? defaults.confirmLabel,
      cancelLabel: options.cancelLabel ?? defaults.cancelLabel,
      tone: options.tone ?? defaults.tone
    };

    return new Promise((resolve) => {
      this.resolver = resolve;
      this.stateSubject.next(dialogState);
    });
  }

  resolve(result: boolean): void {
    const resolver = this.resolver;
    this.resolver = null;
    this.stateSubject.next(null);
    resolver?.(result);
  }

  dismiss(): void {
    this.resolve(false);
  }

  isOpen(): boolean {
    return this.stateSubject.value !== null;
  }
}
