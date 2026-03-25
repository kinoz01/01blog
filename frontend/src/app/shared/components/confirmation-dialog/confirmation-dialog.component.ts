import { CommonModule } from '@angular/common';
import { Component, HostListener, inject } from '@angular/core';

import { ConfirmationService } from '../../../core/services/confirmation.service';

@Component({
  selector: 'app-confirmation-dialog',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './confirmation-dialog.component.html',
  styleUrl: './confirmation-dialog.component.scss'
})
export class ConfirmationDialogComponent {
  private readonly confirmationService = inject(ConfirmationService);
  readonly dialogState$ = this.confirmationService.state$;

  close(result: boolean): void {
    this.confirmationService.resolve(result);
  }

  onBackdropClick(): void {
    this.confirmationService.resolve(false);
  }

  @HostListener('document:keydown.escape', ['$event'])
  onEscape(event: KeyboardEvent): void {
    if (!this.confirmationService.isOpen()) {
      return;
    }
    event.preventDefault();
    this.confirmationService.resolve(false);
  }
}
