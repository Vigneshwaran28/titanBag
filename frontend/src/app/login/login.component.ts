import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  activeTab: 'login' | 'register' | 'admin' = 'login';
  errorMessage = '';
  isSubmitting = false;

  // Regular Login Fields
  loginIdentity = '';
  loginPassword = '';

  // Regular Register Fields
  regUsername = '';
  regEmail = '';
  regPassword = '';
  regDisplayName = '';

  // Admin (God User) Fields
  adminSuperUser = '';
  adminAuthKey = '';

  constructor(
    private apiService: ApiService,
    private router: Router,
    private route: ActivatedRoute
  ) {}

  ngOnInit(): void {
    // Check url query params: e.g. /login?admin=true
    this.route.queryParams.subscribe(params => {
      if (params['admin'] === 'true') {
        this.activeTab = 'admin';
      }
    });

    // Already logged in? Redirect
    if (localStorage.getItem('god_token')) {
      this.router.navigate(['/admin']);
    } else if (localStorage.getItem('user_token')) {
      this.router.navigate(['/dashboard']);
    }
  }

  switchTab(tab: 'login' | 'register' | 'admin'): void {
    this.activeTab = tab;
    this.errorMessage = '';
  }

  // Detect Client OS/Browser as device model details
  private getDeviceMetadata(): { model: string, manufacturer: string } {
    const userAgent = navigator.userAgent;
    let model = 'Web App Client';
    let manufacturer = 'Browser';

    if (userAgent.includes('Windows')) {
      model = 'Windows PC';
      manufacturer = 'Microsoft';
    } else if (userAgent.includes('Macintosh')) {
      model = 'MacBook/iMac';
      manufacturer = 'Apple';
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
      model = 'iOS Device';
      manufacturer = 'Apple';
    } else if (userAgent.includes('Android')) {
      model = 'Android Device';
      manufacturer = 'Google';
    } else if (userAgent.includes('Linux')) {
      model = 'Linux System';
      manufacturer = 'Linux';
    }
    
    // Append browser info
    if (userAgent.includes('Chrome')) {
      model += ' (Chrome)';
    } else if (userAgent.includes('Safari')) {
      model += ' (Safari)';
    } else if (userAgent.includes('Firefox')) {
      model += ' (Firefox)';
    }
    
    return { model, manufacturer };
  }

  handleLogin(event: Event): void {
    event.preventDefault();
    if (this.isSubmitting) return;

    this.isSubmitting = true;
    this.errorMessage = '';

    const deviceMeta = this.getDeviceMetadata();
    const payload = {
      identifier: this.loginIdentity,
      password: this.loginPassword,
      device_model: deviceMeta.model,
      device_manufacturer: deviceMeta.manufacturer
    };

    this.apiService.loginUser(payload).subscribe({
      next: (data) => {
        localStorage.setItem('user_token', data.token);
        localStorage.setItem('user_profile', JSON.stringify(data.user));
        this.isSubmitting = false;
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        this.errorMessage = err.error?.message || 'Login failed. Please check credentials.';
        this.isSubmitting = false;
      }
    });
  }

  handleRegister(event: Event): void {
    event.preventDefault();
    if (this.isSubmitting) return;

    this.isSubmitting = true;
    this.errorMessage = '';

    const deviceMeta = this.getDeviceMetadata();
    const payload = {
      username: this.regUsername,
      email: this.regEmail,
      password: this.regPassword,
      display_name: this.regDisplayName,
      device_model: deviceMeta.model,
      device_manufacturer: deviceMeta.manufacturer
    };

    this.apiService.registerUser(payload).subscribe({
      next: (data) => {
        localStorage.setItem('user_token', data.token);
        localStorage.setItem('user_profile', JSON.stringify(data.user));
        this.isSubmitting = false;
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        this.errorMessage = err.error?.message || 'Registration failed. Verify credentials.';
        this.isSubmitting = false;
      }
    });
  }

  handleAdminLogin(event: Event): void {
    event.preventDefault();
    if (this.isSubmitting) return;

    this.isSubmitting = true;
    this.errorMessage = '';

    const payload = {
      username: this.adminSuperUser,
      password: this.adminAuthKey
    };

    this.apiService.loginAdmin(payload).subscribe({
      next: (data) => {
        localStorage.setItem('god_token', data.token);
        this.isSubmitting = false;
        this.router.navigate(['/admin']);
      },
      error: (err) => {
        this.errorMessage = err.error?.message || 'Admin authentication failed.';
        this.isSubmitting = false;
      }
    });
  }
}
