// Minimal user info stored on the client after auth.
export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: 'USER' | 'ADMIN';
  createdAt: string;
  updatedAt: string;
}

// Shape of the /auth login/register response payload.
export interface AuthResponse {
  token: string;
  tokenType: string;
  expiresIn: number;
  user?: UserProfile;
}

// Login form submission payload.
export interface LoginPayload {
  email: string;
  password: string;
}

// Registration form submission payload.
export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
}

// Client-side auth cache (token, expiry, optional profile).
export interface AuthState {
  token: string;
  expiresAt: number;
  user: UserProfile | null;
}
