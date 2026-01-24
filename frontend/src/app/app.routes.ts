import { Routes } from '@angular/router';

import { authGuard } from './core/guards/auth.guard';
import { guestGuard } from './core/guards/guest.guard';
import { adminGuard } from './core/guards/admin.guard';

export const routes: Routes = [
  {
    path: '',
    canActivate: [authGuard],
    children: [
      {
        path: 'home',
        loadComponent: () => import('./pages/home/home.component').then((m) => m.HomeComponent)
      },
      {
        path: 'posts/:postId',
        loadComponent: () => import('./pages/post-detail/post-detail.component').then((m) => m.PostDetailComponent)
      },
      {
        path: 'users',
        loadComponent: () => import('./pages/user-directory/user-directory.component').then((m) => m.UserDirectoryComponent)
      },
      {
        path: 'notifications',
        loadComponent: () =>
          import('./pages/notifications/notifications.component').then((m) => m.NotificationsComponent)
      },
      {
        path: 'users/:userId',
        loadComponent: () =>
          import('./pages/user-profile/user-profile.component').then((m) => m.UserProfileComponent)
      },
      {
        path: 'admin',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./pages/admin-dashboard/admin-dashboard.component').then((m) => m.AdminDashboardComponent)
      },
      {
        path: '',
        pathMatch: 'full',
        redirectTo: 'home'
      }
    ]
  },
  {
    path: 'login',
    canActivate: [guestGuard],
    loadComponent: () => import('./pages/auth/login/login.component').then((m) => m.LoginComponent)
  },
  {
    path: 'register',
    canActivate: [guestGuard],
    loadComponent: () => import('./pages/auth/register/register.component').then((m) => m.RegisterComponent)
  },
  {
    path: '**',
    redirectTo: 'login'
  }
];
