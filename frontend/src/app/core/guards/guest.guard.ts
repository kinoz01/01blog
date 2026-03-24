import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

// Guard that keeps authenticated users out of guest-only routes (login/register).
export const guestGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Observe the cached authentication flag once.
  return authService.isAuthenticated$.pipe(
    // take(1) so the guard responds immediately without staying subscribed.
    take(1),
    // Redirect authenticated users to /home, otherwise allow navigation.
    map((isAuthenticated) => (isAuthenticated ? router.parseUrl('/home') : true))
  );
};
