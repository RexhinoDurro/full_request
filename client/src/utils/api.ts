// API configuration for Django backend
const API_BASE_URL ='https://cryptofacilities.eu/api';

export interface SubmissionData {
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
}

export interface ApiResponse {
  success: boolean;
  message: string;
  submission_id?: number;
  errors?: Record<string, string[]>;
}

class ApiClient {
  private baseURL: string;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      
      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  async submitForm(formData: SubmissionData): Promise<ApiResponse> {
    return this.makeRequest<ApiResponse>('/submit/', {
      method: 'POST',
      body: JSON.stringify(formData),
    });
  }
}

export const apiClient = new ApiClient(API_BASE_URL);

// Helper function to handle form submission
export const submitFormData = async (formData: SubmissionData): Promise<{
  success: boolean;
  message: string;
  submissionId?: number;
}> => {
  try {
    const response = await apiClient.submitForm(formData);
    
    return {
      success: response.success,
      message: response.message,
      submissionId: response.submission_id,
    };
  } catch (error) {
    console.error('Form submission error:', error);
    
    return {
      success: false,
      message: error instanceof Error ? error.message : 'An unexpected error occurred',
    };
  }
};