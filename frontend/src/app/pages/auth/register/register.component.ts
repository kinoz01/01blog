import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { finalize } from 'rxjs';

import { AuthService } from '../../../core/services/auth.service';
import { RegisterPayload } from '../../../core/models/auth.models';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
// Registration form component that creates a new user and logs them in.
export class RegisterComponent {
  private readonly fb = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  // The form includes a custom validator to ensure passwords match.
  readonly form = this.fb.nonNullable.group(
    {
      name: ['', [Validators.required, Validators.minLength(4), Validators.maxLength(25)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', [Validators.required]]
    },
    {
      validators: [this.matchPasswords('password', 'confirmPassword')]
    }
  );

  isSubmitting = false;
  errorMessage = '';

  // Handles the submit button, validating the form and calling the auth API.
  submit(): void {
    if (this.form.invalid) {
      // Touch fields so validation errors are visible to the user.
      this.form.markAllAsTouched();
      return;
    }

    this.errorMessage = '';
    this.isSubmitting = true;

    const { name, email, password } = this.form.getRawValue();
    const payload: RegisterPayload = { name, email, password };

    this.authService
      .register(payload)
      .pipe(finalize(() => (this.isSubmitting = false)))
      .subscribe({
        next: () => this.handleSuccess(),
        error: (error) => this.handleError(error)
      });
  }

  // On success, clear the form and route to the home feed just like login.
  private handleSuccess(): void {
    this.form.reset();
    this.router.navigateByUrl('/home');
  }

  // Converts API or network errors into user-friendly messaging.
  private handleError(error: unknown): void {
    if (typeof error === 'string') {
      this.errorMessage = error;
      return;
    }

    if (error && typeof error === 'object' && 'error' in error) {
      const payload = (error as { error?: { message?: string; errors?: Record<string, string> } }).error;
      this.errorMessage = payload?.message ?? 'Unable to create your account right now.';
      return;
    }

    this.errorMessage = 'Unable to create your account right now.';
  }

  // Convenience for templates to highlight invalid inputs.
  fieldInvalid(field: 'name' | 'email' | 'password' | 'confirmPassword'): boolean {
    const control = this.form.get(field);
    return !!control && control.invalid && (control.dirty || control.touched);
  }

  // Signals to the template when the password mismatch error should be shown.
  passwordMismatch(): boolean {
    return this.form.hasError('passwordMismatch') && (this.form.dirty || this.form.touched);
  }

  // Custom validator that ensures password/confirmPassword fields stay in sync.
  private matchPasswords(passwordField: string, confirmField: string): ValidatorFn {
    return (group) => {
      const password = group.get(passwordField);
      const confirm = group.get(confirmField);

      if (!password || !confirm) {
        return null;
      }

      const mismatch = password.value !== confirm.value;
      if (mismatch) {
        // Add a passwordMismatch flag to the confirm control so the UI can show feedback.
        confirm.setErrors({ ...(confirm.errors ?? {}), passwordMismatch: true });
      } else {
        const { passwordMismatch, ...rest } = confirm.errors ?? {};
        confirm.setErrors(Object.keys(rest).length ? rest : null);
      }

      return mismatch ? ({ passwordMismatch: true } as ValidationErrors) : null;
    };
  }
}
