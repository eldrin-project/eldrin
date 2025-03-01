import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { AsyncPipe } from '@angular/common';
import { AuthService } from '../../services/auth.service';
import { User } from '../../models/user.model';

@Component({
  selector: 'app-dashboard',
  imports: [AsyncPipe],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent implements OnInit {
  user$: Observable<User | null>;

  constructor(private authService: AuthService) {
    this.user$ = this.authService.currentUser$;
  }

  ngOnInit(): void {
    // In a real application, we would fetch modules data from the backend
    // For example:
    // this.moduleService.getUserModules().subscribe(modules => this.modules = modules);
  }
}
