import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map, switchMap, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

// Route guard that only allows navigation when the current user has the ADMIN role.
export const adminGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.state$.pipe(
    // take(1) ensures we read the current auth state once and complete.
    take(1),
    // switchMap lets us branch into async checks (cached user vs fetch).
    switchMap((state) => {
      // No token present: redirect to login.
      if (!state?.token) {
        return of(router.parseUrl('/login'));
      }
      // Token + cached user: check the role immediately.
      if (state.user) {
        return of(state.user.role === 'ADMIN' ? true : router.parseUrl('/home'));
      }
      // Otherwise hit /auth/me to fetch the profile before deciding.
      return authService.me().pipe(
        map((profile) => (profile.role === 'ADMIN' ? true : router.parseUrl('/home'))),
        catchError(() => {
          authService.logout();
          return of(router.parseUrl('/login'));
        })
      );
    })
  );
};
