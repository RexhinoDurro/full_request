// Fixed API Client (admin/src/utils/api.ts)
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

// 🔧 FIXED: Add interface for Django REST Framework paginated response
export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
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
      console.log('Making request to:', url);
      console.log('With headers:', config.headers);

      const response = await fetch(url, config);
      
      console.log('Response status:', response.status);
      console.log('Response headers:', Object.fromEntries(response.headers.entries()));
      
      // Handle binary responses (like file downloads) - don't try to parse as JSON
      const contentType = response.headers.get('content-type');
      if (contentType && (contentType.includes('spreadsheet') || contentType.includes('excel'))) {
        if (!response.ok) {
          throw new Error(`Download failed: HTTP ${response.status}`);
        }
        return response as any; // Return the response object for binary downloads
      }
      
      const data = await response.json();
      console.log('Response data:', data);
      
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
            
            // Check if retry response is binary
            const retryContentType = retryResponse.headers.get('content-type');
            if (retryContentType && (retryContentType.includes('spreadsheet') || retryContentType.includes('excel'))) {
              return retryResponse as any;
            }
            
            return await retryResponse.json();
          } else {
            // Refresh failed, redirect to login
            this.clearTokenFromStorage();
            window.location.href = '/';
            throw new Error('Authentication failed');
          }
        }
        throw new Error(data.message || data.detail || `HTTP error! status: ${response.status}`);
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

  // 🔧 FIXED: Handle both paginated and direct response formats
  async getSubmissions(filters?: SubmissionFilters): Promise<{ results: Submission[] }> {
    try {
      const queryString = filters ? this.buildQueryString(filters) : '';
      const endpoint = `/admin/submissions/${queryString ? `?${queryString}` : ''}`;
      
      console.log('Fetching submissions from:', endpoint);
      const response = await this.makeRequest<any>(endpoint);
      console.log('Submissions response:', response);
      
      // Handle different response formats
      if (Array.isArray(response)) {
        // Direct array response
        return { results: response };
      } else if (response.results && Array.isArray(response.results)) {
        // Paginated response from Django REST Framework
        return { results: response.results };
      } else if (response.success && response.data && Array.isArray(response.data)) {
        // Custom success response format
        return { results: response.data };
      } else if (response.success && Array.isArray(response.results)) {
        // Custom success response with results
        return { results: response.results };
      } else {
        // Fallback - try to extract any array from the response
        console.warn('Unexpected response format for submissions:', response);
        return { results: [] };
      }
    } catch (error) {
      console.error('Failed to get submissions:', error);
      throw error;
    }
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

  // 🔧 FIXED: Handle both response formats for filter options
  async getFilterOptions(): Promise<FilterOptions> {
    try {
      const response = await this.makeRequest<any>('/admin/filter-options/');
      console.log('Filter options response:', response);
      
      // Handle both formats: { success: true, ...data } or direct data
      if (response.success !== undefined) {
        // New format with success field
        return {
          service_types: response.service_types || [],
          issue_timeframes: response.issue_timeframes || [],
          acknowledgments: response.acknowledgments || [],
          primary_goals: response.primary_goals || [],
          heard_abouts: response.heard_abouts || [],
          communication_methods: response.communication_methods || [],
          countries: response.countries || []
        };
      } else {
        // Legacy format or direct data
        return {
          service_types: response.service_types || [],
          issue_timeframes: response.issue_timeframes || [],
          acknowledgments: response.acknowledgments || [],
          primary_goals: response.primary_goals || [],
          heard_abouts: response.heard_abouts || [],
          communication_methods: response.communication_methods || [],
          countries: response.countries || []
        };
      }
    } catch (error) {
      console.error('Failed to get filter options:', error);
      throw error;
    }
  }

  // 🔧 FIXED: Handle both response formats for stats
  async getStats(filters?: SubmissionFilters): Promise<SubmissionStats> {
    try {
      const queryString = filters ? this.buildQueryString(filters) : '';
      const endpoint = `/admin/stats/${queryString ? `?${queryString}` : ''}`;
      
      console.log('Fetching stats from:', endpoint);
      const response = await this.makeRequest<any>(endpoint);
      console.log('Raw stats response:', response);
      
      // Handle both formats: { success: true, ...data } or direct data
      if (response.success !== undefined) {
        // New format with success field - extract the actual stats
        const statsData = {
          total_submissions: response.total_submissions || 0,
          service_type_breakdown: response.service_type_breakdown || {},
          country_breakdown: response.country_breakdown || {},
          issue_timeframe_breakdown: response.issue_timeframe_breakdown || {},
          daily_submissions: response.daily_submissions || [],
          date_range: response.date_range || { from: '', to: '', preset: '' }
        };
        
        console.log('Processed stats data:', statsData);
        return statsData;
      } else {
        // Legacy format or direct data
        return {
          total_submissions: response.total_submissions || 0,
          service_type_breakdown: response.service_type_breakdown || {},
          country_breakdown: response.country_breakdown || {},
          issue_timeframe_breakdown: response.issue_timeframe_breakdown || {},
          daily_submissions: response.daily_submissions || [],
          date_range: response.date_range || { from: '', to: '', preset: '' }
        };
      }
    } catch (error) {
      console.error('Failed to get stats:', error);
      throw error;
    }
  }

  // 🔧 FIXED: Proper Excel file download implementation
  async downloadSubmissions(filters?: SubmissionFilters): Promise<Blob> {
    const queryString = filters ? this.buildQueryString(filters) : '';
    const endpoint = `/admin/submissions/download/${queryString ? `?${queryString}` : ''}`;
    
    try {
      console.log('Downloading from endpoint:', endpoint);
      
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          // Don't set Content-Type for file downloads
        },
      });

      console.log('Download response status:', response.status);
      console.log('Download response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        // Try to get error message
        let errorMessage = 'Download failed';
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorMessage;
        } catch {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }

      // Check if response is actually an Excel file
      const contentType = response.headers.get('content-type');
      console.log('Content type:', contentType);
      
      if (!contentType || (!contentType.includes('spreadsheet') && !contentType.includes('excel') && !contentType.includes('openxmlformats'))) {
        // If it's JSON, it might be an error response
        try {
          const jsonResponse = await response.json();
          console.log('Unexpected JSON response:', jsonResponse);
          throw new Error(jsonResponse.message || 'Invalid file format received - expected Excel file');
        } catch (jsonError) {
          // If it's not JSON either, assume it's a file but with wrong content type
          console.warn('Unknown content type, proceeding with download');
        }
      }

      // Get the blob
      const blob = await response.blob();
      console.log('Downloaded blob size:', blob.size, 'type:', blob.type);
      
      // Double-check blob size
      if (blob.size === 0) {
        throw new Error('Downloaded file is empty');
      }

      // If blob type is not set, set it manually for Excel
      if (!blob.type || blob.type === 'application/octet-stream') {
        return new Blob([blob], { 
          type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' 
        });
      }

      return blob;
    } catch (error) {
      console.error('Download error:', error);
      throw error;
    }
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }
}

export const adminApiClient = new AdminApiClient(API_BASE_URL);