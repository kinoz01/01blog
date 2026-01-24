import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map, switchMap, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

export const adminGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.state$.pipe(
    take(1),
    switchMap((state) => {
      if (!state?.token) {
        return of(router.parseUrl('/login'));
      }
      if (state.user) {
        return of(state.user.role === 'ADMIN' ? true : router.parseUrl('/home'));
      }
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
