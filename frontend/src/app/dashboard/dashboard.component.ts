import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

interface Journal {
  id: string;
  owner_id?: string;
  title: string;
  amount: number;
  category: string;
  notes?: string;
  payment_method?: string;
  date: string;
  created_at: string;
  updated_at: string;
  deleted: boolean;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  journals: Journal[] = [];
  userProfile: any = null;
  partnerInfo: any = null;
  partnerCodeInput = '';
  
  // Analytics
  totalIncome = 0;
  totalExpenses = 0;
  balance = 0;

  // View States
  isSyncing = false;
  showAddModal = false;
  isEditing = false;
  errorMessage = '';
  successMessage = '';

  // Form Fields
  formId = '';
  formTitle = '';
  formAmount = 0;
  formType: 'income' | 'expense' = 'expense';
  formCategory = 'Food';
  formNotes = '';
  formPaymentMethod = 'Card';
  formDate = new Date().toISOString().substring(0, 16); // yyyy-MM-ddThh:mm

  // Search & Filter
  searchQuery = '';
  filterCategory = 'All';

  categories = ['Food', 'Housing', 'Transportation', 'Entertainment', 'Utilities', 'Salary', 'Investment', 'Other'];
  paymentMethods = ['Cash', 'Card', 'Bank Transfer', 'Mobile Pay'];

  constructor(private apiService: ApiService, private router: Router) {}

  ngOnInit(): void {
    const token = localStorage.getItem('user_token');
    if (!token) {
      this.router.navigate(['/login']);
      return;
    }

    // Load user profile cache
    const profileStr = localStorage.getItem('user_profile');
    if (profileStr) {
      this.userProfile = JSON.parse(profileStr);
    }

    // Load cached journals
    const cached = localStorage.getItem('cached_journals');
    if (cached) {
      this.journals = JSON.parse(cached);
      this.calculateAnalytics();
    }

    this.refreshProfile();
    this.syncData();
  }

  logout(): void {
    localStorage.removeItem('user_token');
    localStorage.removeItem('user_profile');
    localStorage.removeItem('cached_journals');
    localStorage.removeItem('last_synced_at');
    this.router.navigate(['/']);
  }

  refreshProfile(): void {
    const token = localStorage.getItem('user_token');
    if (!token) return;

    this.apiService.getUserProfile(token).subscribe({
      next: (data) => {
        this.userProfile = data.user;
        localStorage.setItem('user_profile', JSON.stringify(data.user));
        this.partnerInfo = data.user.partner || null;
      },
      error: (err) => {
        console.error('Failed to retrieve user profile:', err);
      }
    });
  }

  // Direct Sync Mechanism
  syncData(): void {
    const token = localStorage.getItem('user_token');
    if (!token || this.isSyncing) return;

    this.isSyncing = true;
    const lastSynced = localStorage.getItem('last_synced_at') || '1970-01-01T00:00:00.000Z';

    // Find local modifications since last sync
    const lastSyncTime = new Date(lastSynced).getTime();
    const localModifications = this.journals.filter(j => new Date(j.updated_at).getTime() > lastSyncTime);

    const payload = {
      last_synced_at: lastSynced,
      local_journals: localModifications
    };

    this.apiService.syncJournals(token, payload).subscribe({
      next: (data) => {
        const remoteList: Journal[] = data.remote_journals || [];
        
        // Merge Remote and Local journals lists
        let merged = [...this.journals];
        
        remoteList.forEach(remote => {
          const index = merged.findIndex(j => j.id === remote.id);
          if (index !== -1) {
            // Replace if remote is newer
            if (new Date(remote.updated_at).getTime() >= new Date(merged[index].updated_at).getTime()) {
              merged[index] = remote;
            }
          } else {
            merged.push(remote);
          }
        });

        // Filter out soft deleted records locally
        this.journals = merged.filter(j => !j.deleted);

        // Update caches
        localStorage.setItem('cached_journals', JSON.stringify(this.journals));
        localStorage.setItem('last_synced_at', new Date().toISOString());
        
        this.calculateAnalytics();
        this.isSyncing = false;
      },
      error: (err) => {
        console.error('Sync failed:', err);
        this.isSyncing = false;
      }
    });
  }

  calculateAnalytics(): void {
    let inc = 0;
    let exp = 0;

    // Standard categorisation: Salary, Investment are Income. Rest are Expenses.
    this.journals.forEach(j => {
      if (j.deleted) return;
      const amt = Number(j.amount);
      if (j.category === 'Salary' || j.category === 'Investment') {
        inc += amt;
      } else {
        exp += amt;
      }
    });

    this.totalIncome = inc;
    this.totalExpenses = exp;
    this.balance = inc - exp;
  }

  // Filter & Search helper
  getFilteredJournals(): Journal[] {
    return this.journals
      .filter(j => {
        const queryMatch = j.title.toLowerCase().includes(this.searchQuery.toLowerCase()) || 
                           (j.notes || '').toLowerCase().includes(this.searchQuery.toLowerCase());
        const catMatch = this.filterCategory === 'All' || j.category === this.filterCategory;
        return queryMatch && catMatch;
      })
      .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  }

  openAddModal(journal?: Journal): void {
    this.errorMessage = '';
    this.successMessage = '';
    
    if (journal) {
      this.isEditing = true;
      this.formId = journal.id;
      this.formTitle = journal.title;
      this.formAmount = journal.amount;
      this.formCategory = journal.category;
      this.formNotes = journal.notes || '';
      this.formPaymentMethod = journal.payment_method || 'Card';
      this.formDate = new Date(journal.date).toISOString().substring(0, 16);
      
      const isInc = journal.category === 'Salary' || journal.category === 'Investment';
      this.formType = isInc ? 'income' : 'expense';
    } else {
      this.isEditing = false;
      this.formId = '';
      this.formTitle = '';
      this.formAmount = 0;
      this.formCategory = 'Food';
      this.formNotes = '';
      this.formPaymentMethod = 'Card';
      this.formDate = new Date().toISOString().substring(0, 16);
      this.formType = 'expense';
    }

    this.showAddModal = true;
  }

  closeAddModal(): void {
    this.showAddModal = false;
  }

  saveJournal(): void {
    if (!this.formTitle.trim() || this.formAmount <= 0) {
      this.errorMessage = 'Please provide a valid title and amount.';
      return;
    }

    const timestamp = new Date().toISOString();
    
    if (this.isEditing) {
      // Edit mode
      const index = this.journals.findIndex(j => j.id === this.formId);
      if (index !== -1) {
        this.journals[index] = {
          ...this.journals[index],
          title: this.formTitle,
          amount: this.formAmount,
          category: this.formCategory,
          notes: this.formNotes,
          payment_method: this.formPaymentMethod,
          date: new Date(this.formDate).toISOString(),
          updated_at: timestamp
        };
      }
    } else {
      // Add mode
      const newJournal: Journal = {
        id: crypto.randomUUID(),
        title: this.formTitle,
        amount: this.formAmount,
        category: this.formCategory,
        notes: this.formNotes,
        payment_method: this.formPaymentMethod,
        date: new Date(this.formDate).toISOString(),
        created_at: timestamp,
        updated_at: timestamp,
        deleted: false
      };
      this.journals.push(newJournal);
    }

    // Save cache and sync
    localStorage.setItem('cached_journals', JSON.stringify(this.journals));
    this.calculateAnalytics();
    this.syncData();
    this.closeAddModal();
  }

  deleteJournal(id: string): void {
    const index = this.journals.findIndex(j => j.id === id);
    if (index !== -1) {
      // Soft delete: flag deleted and update sync time
      this.journals[index].deleted = true;
      this.journals[index].updated_at = new Date().toISOString();
      
      // Update cache
      localStorage.setItem('cached_journals', JSON.stringify(this.journals));
      // Remove from list display
      this.journals = this.journals.filter(j => j.id !== id);
      
      this.calculateAnalytics();
      this.syncData();
    }
  }

  // Link Partner Code
  connectPartner(): void {
    this.errorMessage = '';
    this.successMessage = '';
    const token = localStorage.getItem('user_token');
    
    if (!token || !this.partnerCodeInput.trim()) return;

    this.apiService.connectPartner(token, this.partnerCodeInput.trim()).subscribe({
      next: (res: any) => {
        this.successMessage = res.message;
        this.partnerCodeInput = '';
        this.refreshProfile();
        this.syncData(); // pull down partner journals
      },
      error: (err: any) => {
        this.errorMessage = err.error?.message || 'Failed to connect with partner.';
      }
    });
  }

  disconnectPartner(): void {
    this.errorMessage = '';
    this.successMessage = '';
    const token = localStorage.getItem('user_token');
    
    if (!token) return;

    if (confirm('Are you sure you want to disconnect from your partner? All shared syncs will stop.')) {
      this.apiService.disconnectPartner(token).subscribe({
        next: (res: any) => {
          this.successMessage = res.message;
          this.partnerInfo = null;
          this.refreshProfile();
          this.syncData();
        },
        error: (err: any) => {
          this.errorMessage = err.error?.message || 'Disconnect failed.';
        }
      });
    }
  }
}
