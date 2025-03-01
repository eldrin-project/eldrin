import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const currentUser = authService.currentUser;

  // Skip adding token for auth endpoints
  if (req.url.includes('/login') || req.url.includes('/register')) {
    return next(req);
  }

  // Add token if available
  if (currentUser && currentUser.authToken) {
    const authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${currentUser.authToken}`
      }
    });
    
    // Handle token expiration
    return next(authReq).pipe(
      catchError((error: HttpErrorResponse) => {
        // If 401 Unauthorized, try to refresh the token
        if (error.status === 401 && !req.url.includes('/auth/refresh')) {
          return authService.refreshToken().pipe(
            switchMap(token => {
              // Retry the request with the new token
              const retryReq = req.clone({
                setHeaders: {
                  Authorization: `Bearer ${token}`
                }
              });
              return next(retryReq);
            }),
            catchError(refreshError => {
              // If refresh fails, log out and redirect to login
              authService.logout();
              return throwError(() => refreshError);
            })
          );
        }
        
        return throwError(() => error);
      })
    );
  }
  
  return next(req);
};
