// Admin API configuration for Django backend
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthTokens {
  access: string;
  refresh: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  is_staff: boolean;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  tokens?: AuthTokens;
  user?: User;
}

export interface Submission {
  id: number;
  name: string;
  email: string;
  phone: string;
  country: string;
  short_summary: string;
  submitted_at: string;
}

export interface SubmissionDetail {
  id: number;
  step1: string;
  step2: string;
  step3: string;
  step4: string;
  step5: string;
  step6: string;
  step7: string;
  step8: string;
  name: string;
  email: string;
  country: string;
  phone: string;
  submitted_at: string;
  ip_address?: string;
}

export interface SubmissionStats {
  total_submissions: number;
  service_type_breakdown: Record<string, number>;
  country_breakdown: Record<string, number>;
  issue_timeframe_breakdown: Record<string, number>;
  daily_submissions: Array<{ date: string; count: number }>;
  date_range: {
    from: string;
    to: string;
    preset: string;
  };
}

export interface FilterOptions {
  service_types: string[];
  issue_timeframes: string[];
  acknowledgments: string[];
  primary_goals: string[];
  heard_abouts: string[];
  communication_methods: string[];
  countries: Array<{ code: string; display: string }>;
}

export interface SubmissionFilters {
  date_from?: string;
  date_to?: string;
  date_preset?: 'today' | '1_week' | '2_weeks' | '30_days';
  service_type?: string;
  issue_timeframe?: string;
  acknowledgment?: string;
  primary_goal?: string;
  heard_about?: string;
  communication_method?: string;
  country?: string;
  search?: string;
}

class AdminApiClient {
  private baseURL: string;
  private accessToken: string | null = null;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
    this.loadTokenFromStorage();
  }

  private loadTokenFromStorage() {
    this.accessToken = localStorage.getItem('admin_access_token');
  }

  private saveTokenToStorage(tokens: AuthTokens) {
    localStorage.setItem('admin_access_token', tokens.access);
    localStorage.setItem('admin_refresh_token', tokens.refresh);
    this.accessToken = tokens.access;
  }

  private clearTokenFromStorage() {
    localStorage.removeItem('admin_access_token');
    localStorage.removeItem('admin_refresh_token');
    this.accessToken = null;
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.accessToken && { Authorization: `Bearer ${this.accessToken}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();
      
      if (!response.ok) {
        if (response.status === 401) {
          // Token expired, try to refresh
          const refreshed = await this.refreshToken();
          if (refreshed) {
            // Retry the original request with new token
            const retryConfig = {
              ...config,
              headers: {
                ...config.headers,
                Authorization: `Bearer ${this.accessToken}`,
              },
            };
            const retryResponse = await fetch(url, retryConfig);
            return await retryResponse.json();
          } else {
            // Refresh failed, redirect to login
            this.clearTokenFromStorage();
            window.location.href = '/';
            throw new Error('Authentication failed');
          }
        }
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      
      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  private buildQueryString(params: Record<string, any>): string {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.append(key, value.toString());
      }
    });
    return searchParams.toString();
  }

  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    const response = await this.makeRequest<LoginResponse>('/auth/login/', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    if (response.success && response.tokens) {
      this.saveTokenToStorage(response.tokens);
    }

    return response;
  }

  async logout(): Promise<void> {
    try {
      const refreshToken = localStorage.getItem('admin_refresh_token');
      await this.makeRequest('/auth/logout/', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearTokenFromStorage();
    }
  }

  private async refreshToken(): Promise<boolean> {
    try {
      const refreshToken = localStorage.getItem('admin_refresh_token');
      if (!refreshToken) return false;

      const response = await fetch(`${this.baseURL}/auth/refresh/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh: refreshToken }),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('admin_access_token', data.access);
        this.accessToken = data.access;
        return true;
      }
    } catch (error) {
      console.error('Token refresh error:', error);
    }
    return false;
  }

  async getProfile(): Promise<{ success: boolean; user?: User }> {
    return this.makeRequest('/auth/profile/');
  }

  async getSubmissions(filters?: SubmissionFilters): Promise<{ results: Submission[] }> {
    const queryString = filters ? this.buildQueryString(filters) : '';
    const endpoint = `/admin/submissions/${queryString ? `?${queryString}` : ''}`;
    return this.makeRequest(endpoint);
  }

  async getSubmissionDetail(id: number): Promise<SubmissionDetail> {
    return this.makeRequest(`/admin/submissions/${id}/`);
  }

  async deleteSubmission(id: number): Promise<{ success: boolean; message: string }> {
    return this.makeRequest(`/admin/submissions/${id}/delete/`, {
      method: 'DELETE',
    });
  }

  async deleteAllSubmissions(confirmation: string): Promise<{ success: boolean; message: string }> {
    return this.makeRequest('/admin/submissions/delete-all/', {
      method: 'POST',
      body: JSON.stringify({ confirmation }),
    });
  }

  async getFilterOptions(): Promise<FilterOptions> {
    return this.makeRequest('/admin/filter-options/');
  }

  async getStats(filters?: SubmissionFilters): Promise<SubmissionStats> {
    const queryString = filters ? this.buildQueryString(filters) : '';
    const endpoint = `/admin/stats/${queryString ? `?${queryString}` : ''}`;
    return this.makeRequest(endpoint);
  }

  async downloadSubmissions(filters?: SubmissionFilters): Promise<Blob> {
    const queryString = filters ? this.buildQueryString(filters) : '';
    const endpoint = `/admin/submissions/download/${queryString ? `?${queryString}` : ''}`;
    
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Download failed');
    }

    return response.blob();
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }
}

export const adminApiClient = new AdminApiClient(API_BASE_URL);