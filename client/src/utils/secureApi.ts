// client/src/utils/secureApi.ts - Enhanced API client with security
import { SecurityUtils } from './security';

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: Record<string, string[]>;
}

class SecureApiClient {
  private baseURL: string;
  private maxRetries: number = 3;
  private retryDelay: number = 1000;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseURL}${endpoint}`;
    
    // Security checks
    if (!SecurityUtils.checkRateLimit('api_request', 100, 60000)) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...SecurityUtils.getSecureHeaders(),
        ...options.headers,
      },
      credentials: 'include', // Include cookies for CSRF
    };

    // Add CSRF token if available
    const csrfToken = SecurityUtils.getCSRFToken();
    if (csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method || 'GET')) {
      config.headers = {
        ...config.headers,
        'X-CSRFToken': csrfToken
      };
    }

    let lastError: Error;
    
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await fetch(url, config);
        
        // Check for security headers in response
        this.validateResponseHeaders(response);
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        return data;
        
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on client errors (4xx)
        if (error instanceof Error && error.message.includes('HTTP 4')) {
          break;
        }
        
        if (attempt < this.maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, this.retryDelay * (attempt + 1)));
        }
      }
    }
    
    throw lastError!;
  }

  private validateResponseHeaders(response: Response): void {
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection'
    ];

    for (const header of requiredHeaders) {
      if (!response.headers.get(header)) {
        console.warn(`Missing security header: ${header}`);
      }
    }
  }

  async submitForm(formData: Record<string, any>): Promise<ApiResponse> {
    // Client-side validation
    const sanitizedData: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(formData)) {
      if (typeof value === 'string') {
        sanitizedData[key] = SecurityUtils.sanitizeInput(value);
      } else {
        sanitizedData[key] = value;
      }
    }

    // Validate required fields
    const nameValidation = SecurityUtils.validateName(sanitizedData.name);
    if (!nameValidation.isValid) {
      throw new Error(nameValidation.error);
    }

    const emailValidation = SecurityUtils.validateEmail(sanitizedData.email);
    if (!emailValidation.isValid) {
      throw new Error(emailValidation.error);
    }

    const phoneValidation = SecurityUtils.validatePhone(sanitizedData.phone);
    if (!phoneValidation.isValid) {
      throw new Error(phoneValidation.error);
    }

    // Check for spam
    const allText = Object.values(sanitizedData).join(' ');
    if (SecurityUtils.detectSpam(allText)) {
      throw new Error('Submission blocked by spam filter');
    }

    // Rate limiting for form submissions
    if (!SecurityUtils.checkRateLimit('form_submit', 5, 300000)) { // 5 per 5 minutes
      throw new Error('Too many form submissions. Please wait before trying again.');
    }

    return this.makeRequest('/submit/', {
      method: 'POST',
      body: JSON.stringify(sanitizedData),
    });
  }
}

export const secureApiClient = new SecureApiClient(
  import.meta.env.VITE_API_URL || 'http://localhost:8000/api'
);