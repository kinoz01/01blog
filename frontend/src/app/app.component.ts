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
export class AppComponent {
  readonly title = 'Blog';
  readonly currentYear = new Date().getFullYear();
  isAuthRoute = true;
  isAuthenticated = false;
  isMenuOpen = false;
  currentUserId: string | null = null;
  isAdmin = false;
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);

  constructor() {
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

  private updateLayout(): void {
    const currentUrl = this.router.url.split('?')[0];
    this.isAuthRoute = currentUrl === '/login' || currentUrl === '/register' || currentUrl === '/';
    this.isMenuOpen = false;
  }

  toggleMenu(): void {
    this.isMenuOpen = !this.isMenuOpen;
  }

  closeMenu(): void {
    this.isMenuOpen = false;
  }

  logout(): void {
    this.authService.logout();
    this.closeMenu();
    this.router.navigateByUrl('/login');
  }
}
