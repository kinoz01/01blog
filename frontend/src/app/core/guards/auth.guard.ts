import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map, switchMap, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

// Guard that ensures the user is authenticated before activating a route.
export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Look at the current auth state stream to decide what to do.
  return authService.state$.pipe(
    // take(1) so the guard responds with the latest value and completes.
    take(1),
    // switchMap allows us to run async checks (cached user vs API call).
    switchMap((state) => {
      // No token at all: force login.
      if (!state || !state.token) {
        return of(router.parseUrl('/login'));
      }
      const needsValidation = !state.profileValidated;
      // Token plus in-memory user means we can allow immediately if we've validated this session.
      if (state.user && !needsValidation) {
        return of(true);
      }
      // Otherwise fetch /auth/me to hydrate the user before proceeding.
      return authService.me().pipe(
        // Successful profile fetch means the user is authenticated.
        map(() => true),
        catchError((error) => {
          // For auth/permission errors, log out and redirect to login.
          if (error.status === 401 || error.status === 403) {
            authService.logout();
            return of(router.parseUrl('/login'));
          }
          // Other errors are ignored so navigation can continue.
          return of(true);
        })
      );
    })
  );
};
