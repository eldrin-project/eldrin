import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, map, tap, throwError } from 'rxjs';
import { User } from '../models/user.model';

interface AuthResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_URL = 'http://localhost:3000/api';
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$: Observable<User | null> = this.currentUserSubject.asObservable();
  
  constructor(private http: HttpClient) {
    // Check if user is already logged in
    const storedUser = localStorage.getItem('currentUser');
    if (storedUser) {
      this.currentUserSubject.next(JSON.parse(storedUser));
    }
  }

  public get currentUser(): User | null {
    return this.currentUserSubject.value;
  }

  register(email: string, password: string, firstName?: string, lastName?: string): Observable<User> {
    // Make sure content type is set to application/json
    const headers = { 'Content-Type': 'application/json' };
    
    return this.http.post<AuthResponse>(`${this.API_URL}/users/register`, {
      email,
      password,
      username: firstName // Backend expects username, not firstName/lastName
    }, { headers }).pipe(
      tap(response => {
        const user = {
          ...response.user,
          authToken: response.access_token
        };
        this.setCurrentUser(user);
        // Store the refresh token separately
        localStorage.setItem('refreshToken', response.refresh_token);
      }),
      // Map the response to just return the user
      map(response => response.user)
    );
  }

  login(email: string, password: string): Observable<User> {
    // Make sure content type is set to application/json
    const headers = { 'Content-Type': 'application/json' };
    
    return this.http.post<AuthResponse>(`${this.API_URL}/users/login`, {
      email,
      password
    }, { headers }).pipe(
      tap(response => {
        const user = {
          ...response.user,
          authToken: response.access_token
        };
        this.setCurrentUser(user);
        // Store the refresh token separately
        localStorage.setItem('refreshToken', response.refresh_token);
      }),
      // Map the response to just return the user
      map(response => response.user)
    );
  }

  loginWithGoogle(): Observable<User> {
    // Redirect to Google OAuth endpoint
    window.location.href = `${this.API_URL}/users/auth/google/authorize`;
    return throwError(() => new Error('Redirecting to Google login...'));
  }

  loginWithGithub(): Observable<User> {
    // Redirect to GitHub OAuth endpoint
    window.location.href = `${this.API_URL}/users/auth/github/authorize`;
    return throwError(() => new Error('Redirecting to GitHub login...'));
  }

  refreshToken(): Observable<string> {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token available'));
    }

    // Make sure content type is set to application/json
    const headers = { 'Content-Type': 'application/json' };
    
    return this.http.post<TokenResponse>(
      `${this.API_URL}/users/auth/refresh`,
      { refresh_token: refreshToken },
      { headers }
    ).pipe(
      tap(response => {
        // Update the stored refresh token
        localStorage.setItem('refreshToken', response.refresh_token);
        
        // Update the current user's auth token
        if (this.currentUser) {
          const updatedUser = {
            ...this.currentUser,
            authToken: response.access_token
          };
          this.setCurrentUser(updatedUser);
        }
      }),
      map(response => response.access_token)
    );
  }

  logout(): void {
    localStorage.removeItem('currentUser');
    localStorage.removeItem('refreshToken');
    this.currentUserSubject.next(null);
  }

  isAuthenticated(): boolean {
    return !!this.currentUser;
  }
  
  // Public method for setting user from external auth providers
  setAuthenticatedUser(user: User): void {
    this.setCurrentUser(user);
  }

  private setCurrentUser(user: User): void {
    localStorage.setItem('currentUser', JSON.stringify(user));
    this.currentUserSubject.next(user);
  }
}
