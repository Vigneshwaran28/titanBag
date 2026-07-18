import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-forgot-password',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.css']
})
export class ForgotPasswordComponent {
  email = '';
  errorMessage = '';
  successMessage = '';
  isSubmitting = false;

  constructor(private apiService: ApiService) {}

  handleSubmit(event: Event): void {
    event.preventDefault();
    if (!this.email.trim() || this.isSubmitting) return;

    this.isSubmitting = true;
    this.errorMessage = '';
    this.successMessage = '';

    this.apiService.forgotPassword(this.email.trim()).subscribe({
      next: (res: any) => {
        this.successMessage = res.message || 'If that email exists, we have sent a link to reset your password.';
        this.email = '';
        this.isSubmitting = false;
      },
      error: (err: any) => {
        this.errorMessage = err.error?.message || 'Failed to request password reset link.';
        this.isSubmitting = false;
      }
    });
  }
}
