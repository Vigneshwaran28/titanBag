import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private baseApiUrl = ''; // Dynamic relative URL when deployed together

  constructor(private http: HttpClient) {}

  // Weather Queries
  getIpGeolocation(): Observable<any> {
    return this.http.get('https://ipapi.co/json/');
  }

  getWeather(lat: number, lon: number): Observable<any> {
    return this.http.get(`https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true&hourly=temperature_2m,relative_humidity_2m,weather_code`);
  }

  // News Query
  getTopNews(): Observable<any> {
    return this.http.get('https://ok.surf/api/v1/cors/news-feed');
  }

  // Regular User Auth
  registerUser(payload: any): Observable<any> {
    return this.http.post(`${this.baseApiUrl}/register`, payload);
  }

  loginUser(payload: any): Observable<any> {
    return this.http.post(`${this.baseApiUrl}/login`, payload);
  }

  forgotPassword(email: string): Observable<any> {
    return this.http.post(`${this.baseApiUrl}/api/auth/forgot-password`, { email });
  }

  resetPassword(payload: any): Observable<any> {
    return this.http.post(`${this.baseApiUrl}/api/auth/reset-password`, payload);
  }

  getUserProfile(token: string): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.get(`${this.baseApiUrl}/profile`, { headers });
  }

  connectPartner(token: string, partnerCode: string): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.post(`${this.baseApiUrl}/partner/connect`, { partner_share_code: partnerCode }, { headers });
  }

  disconnectPartner(token: string): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.post(`${this.baseApiUrl}/partner/disconnect`, {}, { headers });
  }

  // Sync Journals
  syncJournals(token: string, payload: any): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.post(`${this.baseApiUrl}/sync`, payload, { headers });
  }

  // Admin (God User) Auth
  loginAdmin(payload: any): Observable<any> {
    return this.http.post(`${this.baseApiUrl}/api/god/login`, payload);
  }

  getAdminUsers(token: string): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.get(`${this.baseApiUrl}/api/god/users`, { headers });
  }

  sendTestEmail(token: string, payload: { to: string, subject: string, html: string }): Observable<any> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.post(`${this.baseApiUrl}/api/god/test-email`, payload, { headers });
  }

  // System Stats
  getSystemInfo(): Observable<any> {
    return this.http.get(`${this.baseApiUrl}/api/info`);
  }
}
