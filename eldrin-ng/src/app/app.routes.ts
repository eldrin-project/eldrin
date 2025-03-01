import { Routes } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { AboutComponent } from './components/about/about.component';
import { AuthCallbackComponent } from './components/auth-callback/auth-callback.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },
  { path: 'about', component: AboutComponent },
  { path: 'auth-callback', component: AuthCallbackComponent },
  { path: '**', redirectTo: '/dashboard' }
];
