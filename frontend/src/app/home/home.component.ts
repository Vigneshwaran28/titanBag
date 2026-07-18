import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  weatherData: any = null;
  locationName: string = 'Detecting location...';
  newsArticles: any[] = [];
  isLoadingWeather = true;
  isLoadingNews = true;
  isUserLoggedIn = false;
  isAdminLoggedIn = false;

  // Weather codes mapping to conditions & icons
  private weatherCodes: { [key: number]: { desc: string, icon: string } } = {
    0: { desc: 'Clear Sky', icon: 'sun' },
    1: { desc: 'Mainly Clear', icon: 'cloud-sun' },
    2: { desc: 'Partly Cloudy', icon: 'cloud' },
    3: { desc: 'Overcast', icon: 'cloudy' },
    45: { desc: 'Foggy', icon: 'cloud-drizzle' },
    48: { desc: 'Depositing Rime Fog', icon: 'cloud-drizzle' },
    51: { desc: 'Light Drizzle', icon: 'cloud-drizzle' },
    53: { desc: 'Moderate Drizzle', icon: 'cloud-drizzle' },
    55: { desc: 'Dense Drizzle', icon: 'cloud-drizzle' },
    61: { desc: 'Slight Rain', icon: 'cloud-rain' },
    63: { desc: 'Moderate Rain', icon: 'cloud-rain' },
    65: { desc: 'Heavy Rain', icon: 'cloud-rain' },
    71: { desc: 'Slight Snowfall', icon: 'snowflake' },
    73: { desc: 'Moderate Snowfall', icon: 'snowflake' },
    75: { desc: 'Heavy Snowfall', icon: 'snowflake' },
    80: { desc: 'Slight Showers', icon: 'cloud-lightning-rain' },
    81: { desc: 'Moderate Showers', icon: 'cloud-lightning-rain' },
    82: { desc: 'Violent Showers', icon: 'cloud-lightning-rain' },
    95: { desc: 'Thunderstorm', icon: 'cloud-lightning' }
  };

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.checkAuthStatus();
    this.loadLocationAndWeather();
    this.loadNews();
  }

  checkAuthStatus(): void {
    this.isUserLoggedIn = !!localStorage.getItem('user_token');
    this.isAdminLoggedIn = !!localStorage.getItem('god_token');
  }

  loadLocationAndWeather(): void {
    if ('geolocation' in navigator) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const lat = position.coords.latitude;
          const lon = position.coords.longitude;
          this.locationName = 'Current Location';
          this.fetchWeather(lat, lon);
        },
        (error) => {
          console.warn('Geolocation failed or blocked, falling back to IP lookup:', error.message);
          this.fetchIpLocation();
        },
        { timeout: 5000 }
      );
    } else {
      this.fetchIpLocation();
    }
  }

  fetchIpLocation(): void {
    this.apiService.getIpGeolocation().subscribe({
      next: (geo) => {
        this.locationName = `${geo.city}, ${geo.country_name}`;
        this.fetchWeather(geo.latitude, geo.longitude);
      },
      error: (err) => {
        console.error('IP Geolocation failed:', err);
        this.locationName = 'Global Overview';
        this.fetchWeather(35.6895, 139.6917); // Default Tokyo
      }
    });
  }

  fetchWeather(lat: number, lon: number): void {
    this.isLoadingWeather = true;
    this.apiService.getWeather(lat, lon).subscribe({
      next: (weather) => {
        const current = weather.current_weather;
        const code = current.weathercode;
        const mapped = this.weatherCodes[code] || { desc: 'Unknown', icon: 'cloud' };

        this.weatherData = {
          temp: Math.round(current.temperature),
          desc: mapped.desc,
          icon: mapped.icon,
          wind: current.windspeed,
          time: current.time
        };
        this.isLoadingWeather = false;
      },
      error: (err) => {
        console.error('Weather fetch failed:', err);
        this.isLoadingWeather = false;
      }
    });
  }

  loadNews(): void {
    this.isLoadingNews = true;
    this.apiService.getTopNews().subscribe({
      next: (news) => {
        // Collect news from various categories (e.g., Technology, Business, US, World)
        const categories = ['Technology', 'Business', 'World', 'US'];
        let collected: any[] = [];
        
        categories.forEach(cat => {
          if (news[cat] && Array.isArray(news[cat])) {
            collected = collected.concat(news[cat].slice(0, 3));
          }
        });

        // Shuffle and take top 6 news articles
        this.newsArticles = collected
          .sort(() => 0.5 - Math.random())
          .slice(0, 6);
        
        this.isLoadingNews = false;
      },
      error: (err) => {
        console.error('News fetch failed:', err);
        this.isLoadingNews = false;
      }
    });
  }

  getWeatherIconClass(iconName: string): string {
    return iconName; // returns name of lucide icon to draw
  }
}
