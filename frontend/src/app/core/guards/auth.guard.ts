import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { of } from 'rxjs';
import { catchError, map, switchMap, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.isAuthenticated$.pipe(
    take(1),
    switchMap((isAuthenticated) => {
      if (!isAuthenticated) {
        return of(router.parseUrl('/login'));
      }
      return authService.me().pipe(
        map(() => true),
        catchError(() => {
          authService.logout();
          return of(router.parseUrl('/login'));
        })
      );
    })
  );
};
