import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { User } from '../../models/user.model';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-auth-callback',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="auth-callback">
      <h2>Authentication Successful</h2>
      <p>Please wait while we redirect you...</p>
    </div>
  `,
  styles: [`
    .auth-callback {
      text-align: center;
      margin-top: 50px;
    }
  `]
})
export class AuthCallbackComponent implements OnInit {
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    console.log('Auth callback component initialized');
    
    // Get parameters from the URL
    this.route.queryParamMap.subscribe(params => {
      console.log('Query parameters:', params);
      
      const accessToken = params.get('access_token');
      const refreshToken = params.get('refresh_token');
      const userId = params.get('user_id');
      const email = params.get('email');
      const username = params.get('username');
      
      console.log('Extracted tokens:', { accessToken: !!accessToken, refreshToken: !!refreshToken, userId, email, username });

      if (accessToken && refreshToken && userId) {
        // Create user object
        const user: User = {
          id: userId,
          email: email || '',
          username: username || '',
          authToken: accessToken,
          // Add other user properties as needed
        };

        // Use AuthService to set the current user and store tokens
        this.authService.setAuthenticatedUser(user);
        localStorage.setItem('refreshToken', refreshToken);

        console.log('Authentication successful. Redirecting to dashboard...');

        // Check if authentication is successful
        console.log('Is authenticated after setting user:', this.authService.isAuthenticated());
        
        // Navigate to dashboard
        this.router.navigate(['/dashboard']);
      } else {
        console.error('Missing required authentication parameters');
        this.router.navigate(['/login']);
      }
    });
  }
}