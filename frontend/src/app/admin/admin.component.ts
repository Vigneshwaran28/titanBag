import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

interface UserRecord {
  username: string;
  device_model: string;
  device_manufacturer: string;
  updated_at: string;
}

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './admin.component.html',
  styleUrls: ['./admin.component.css']
})
export class AdminComponent implements OnInit {
  users: UserRecord[] = [];
  systemInfo: any = null;
  searchQuery = '';
  isLoading = true;
  errorMessage = '';

  // Email Diagnostic Console bindings
  testEmailTo = '';
  testEmailSubject = 'Resend Service Test 🎒';
  testEmailHtml = `<div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 30px; border-radius: 12px; max-width: 600px; margin: 0 auto; background-color: #07090e; color: #f3f4f6; border: 1px solid #1e2633;">
  <div style="text-align: center; margin-bottom: 20px;">
    <div style="background: linear-gradient(135deg, #a855f7, #6366f1); width: 48px; height: 48px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 20px;">T</div>
    <h2 style="margin-top: 15px; color: #a5b4fc;">TitanBag System Diagnostics</h2>
  </div>
  <p>Hello! This is a test email sent to verify that the <strong>Resend email service</strong> is operating correctly.</p>
  <p style="background-color: #0f131a; padding: 12px; border-radius: 6px; border: 1px solid #1e2633; font-family: monospace; font-size: 13px; color: #34d399;">
    Status: INTEGRATION_OPERATIONAL
  </p>
  <hr style="border: 0; border-top: 1px solid #1e2633; margin: 25px 0;" />
  <p style="font-size: 11px; color: #6b7280; text-align: center;">TitanBag Secure Cloud Systems. Administrative Diagnostic Dispatch.</p>
</div>`;
  isSendingEmail = false;
  emailSendResult: { success: boolean; message: string } | null = null;

  constructor(private apiService: ApiService, private router: Router) {}

  ngOnInit(): void {
    const token = localStorage.getItem('god_token');
    if (!token) {
      this.router.navigate(['/login'], { queryParams: { admin: 'true' } });
      return;
    }

    this.loadAdminData(token);
    this.loadSystemStats();
  }

  logout(): void {
    localStorage.removeItem('god_token');
    this.router.navigate(['/']);
  }

  loadAdminData(token: string): void {
    this.isLoading = true;
    this.apiService.getAdminUsers(token).subscribe({
      next: (data) => {
        this.users = data.users || [];
        this.isLoading = false;
      },
      error: (err) => {
        console.error('Failed to load admin user data:', err);
        this.errorMessage = err.error?.message || 'Access authorization expired. Please log in again.';
        this.isLoading = false;
        this.logout();
      }
    });
  }

  loadSystemStats(): void {
    this.apiService.getSystemInfo().subscribe({
      next: (data) => {
        this.systemInfo = data;
      },
      error: (err) => {
        console.error('Failed to retrieve system status stats:', err);
      }
    });
  }

  getFilteredUsers(): UserRecord[] {
    return this.users.filter(u => {
      const q = this.searchQuery.toLowerCase();
      return u.username.toLowerCase().includes(q) || 
             u.device_model.toLowerCase().includes(q) || 
             u.device_manufacturer.toLowerCase().includes(q);
    });
  }

  getLineNumbers(): number[] {
    const linesCount = this.testEmailHtml.split('\n').length;
    const count = Math.max(linesCount, 12);
    return Array.from({ length: count }, (_, i) => i + 1);
  }

  sendTestEmail(): void {
    if (!this.testEmailTo.trim() || !this.testEmailSubject.trim() || !this.testEmailHtml.trim()) {
      this.emailSendResult = { success: false, message: 'All email fields (recipient, subject, html body) are required.' };
      return;
    }

    const token = localStorage.getItem('god_token');
    if (!token) {
      this.errorMessage = 'Authorization token not found. Please log in again.';
      this.logout();
      return;
    }

    this.isSendingEmail = true;
    this.emailSendResult = null;

    const payload = {
      to: this.testEmailTo.trim(),
      subject: this.testEmailSubject.trim(),
      html: this.testEmailHtml
    };

    this.apiService.sendTestEmail(token, payload).subscribe({
      next: (res) => {
        this.isSendingEmail = false;
        this.emailSendResult = { success: true, message: 'Email dispatched successfully! API Response: ' + JSON.stringify(res.data || res) };
      },
      error: (err) => {
        this.isSendingEmail = false;
        this.emailSendResult = { success: false, message: err.error?.message || err.message || 'Failed to dispatch email.' };
      }
    });
  }
}
