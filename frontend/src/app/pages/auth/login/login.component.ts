import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { finalize } from 'rxjs';

import { AuthService } from '../../../core/services/auth.service';
import { LoginPayload } from '../../../core/models/auth.models';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
// Login UI component responsible for collecting credentials and initiating auth.
export class LoginComponent {
  private readonly fb = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  // Reactive form ensures validation feedback and typed controls.
  readonly form = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(8)]]
  });

  isSubmitting = false;
  errorMessage = '';

  // Handles the submit button, validating inputs before calling the API.
  submit(): void {
    if (this.form.invalid) {
      // Mark fields as touched so validation errors show up immediately.
      this.form.markAllAsTouched();
      return;
    }

    this.errorMessage = '';
    this.isSubmitting = true;

    const payload: LoginPayload = this.form.getRawValue();

    this.authService
      .login(payload)
      .pipe(finalize(() => (this.isSubmitting = false)))
      .subscribe({
        next: () => this.handleSuccess(),
        error: (error) => this.handleError(error)
      });
  }

  // On success, clear the form and redirect the user to the home feed.
  private handleSuccess(): void {
    this.form.reset();
    this.router.navigateByUrl('/home');
  }

  // Parses error responses into a friendly message for the user.
  private handleError(error: unknown): void {
    if (typeof error === 'string') {
      this.errorMessage = error;
      return;
    }

    if (error && typeof error === 'object' && 'error' in error) {
      const payload = (error as { error?: { message?: string; errors?: Record<string, string> } }).error;
      this.errorMessage = payload?.message ?? 'Unable to sign in. Please try again.';
      return;
    }

    this.errorMessage = 'Unable to sign in. Please try again.';
  }

  // Utility for templates to show validation errors when the user interacts with a field.
  fieldInvalid(field: 'email' | 'password'): boolean {
    const control = this.form.get(field);
    return !!control && control.invalid && (control.dirty || control.touched);
  }
}
