import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';

import { AuthService } from './core/services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
// Root component that manages global layout, navigation, and authentication state.
export class AppComponent {
  readonly title = 'Maaref';
  readonly currentYear = new Date().getFullYear();
  isAuthRoute = true;
  isAuthenticated = false;
  isMenuOpen = false;
  currentUserId: string | null = null;
  isAdmin = false;
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);

  constructor() { // Subscribe to authentication and routing changes to update layout and navigation state accordingly.
    this.authService.isAuthenticated$.subscribe((status) => (this.isAuthenticated = status));
    this.authService.user$.subscribe((user) => {
      this.currentUserId = user?.id ?? null;
      this.isAdmin = user?.role === 'ADMIN';
    });
    this.router.events
      .pipe(filter((event): event is NavigationEnd => event instanceof NavigationEnd))
      .subscribe(() => this.updateLayout());
    this.updateLayout();
  }
  // Updates layout state based on the current route, determining if we're on an auth page and closing the menu.
  private updateLayout(): void {
    const currentUrl = this.router.url.split('?')[0];
    this.isAuthRoute = currentUrl === '/login' || currentUrl === '/register';
    this.isMenuOpen = false;
  }

  // Toggles the mobile menu open/closed when the menu button is clicked.
  toggleMenu(): void {
    this.isMenuOpen = !this.isMenuOpen;
  }
  // Closes the mobile menu, typically called when a navigation link is clicked or when clicking outside the menu.
  closeMenu(): void {
    this.isMenuOpen = false;
  }
  // Logs the user out by calling the AuthService, then navigates to the login page and closes any open menus.
  logout(): void {
    this.authService.logout();
    this.closeMenu();
    this.router.navigateByUrl('/login');
  }
}
