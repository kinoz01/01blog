import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map, switchMap, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.state$.pipe(
    take(1),
    switchMap((state) => {
      if (!state?.token) {
        return of(router.parseUrl('/login'));
      }
      if (state.user) {
        return of(true);
      }
      return authService.me().pipe(
        map(() => true),
        catchError((error) => {
          if (error.status === 401 || error.status === 403) {
            authService.logout();
            return of(router.parseUrl('/login'));
          }
          return of(true);
        })
      );
    })
  );
};
