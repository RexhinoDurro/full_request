// client/src/utils/security.ts - Client-side security utilities
import DOMPurify from 'dompurify';

/**
 * Security utilities for client-side protection
 */
export class SecurityUtils {
  private static readonly MAX_INPUT_LENGTH = 1000;
  private static readonly MAX_EMAIL_LENGTH = 254;
  private static readonly MAX_NAME_LENGTH = 100;
  private static readonly MAX_PHONE_LENGTH = 20;

  /**
   * Sanitize user input to prevent XSS attacks
   */
  static sanitizeInput(input: string): string {
    if (!input) return '';
    
    // Use DOMPurify to clean HTML
    const cleaned = DOMPurify.sanitize(input, { 
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true
    });
    
    // Additional cleaning
    return cleaned
      .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim()
      .substring(0, this.MAX_INPUT_LENGTH);
  }

  /**
   * Validate email format with additional security checks
   */
  static validateEmail(email: string): { isValid: boolean; error?: string } {
    if (!email) {
      return { isValid: false, error: 'Email is required' };
    }

    const sanitized = this.sanitizeInput(email);
    
    if (sanitized.length > this.MAX_EMAIL_LENGTH) {
      return { isValid: false, error: 'Email address too long' };
    }

    // RFC 5322 compliant regex
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(sanitized)) {
      return { isValid: false, error: 'Invalid email format' };
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /data:/i,
      /vbscript:/i
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(sanitized)) {
        return { isValid: false, error: 'Email contains invalid characters' };
      }
    }

    return { isValid: true };
  }

  /**
   * Validate name with security checks
   */
  static validateName(name: string): { isValid: boolean; error?: string } {
    if (!name) {
      return { isValid: false, error: 'Name is required' };
    }

    const sanitized = this.sanitizeInput(name);
    
    if (sanitized.length < 2) {
      return { isValid: false, error: 'Name must be at least 2 characters' };
    }

    if (sanitized.length > this.MAX_NAME_LENGTH) {
      return { isValid: false, error: 'Name too long' };
    }

    // Only allow letters, spaces, hyphens, apostrophes, and periods
    const nameRegex = /^[a-zA-Z\s\-'\.]+$/;
    if (!nameRegex.test(sanitized)) {
      return { isValid: false, error: 'Name contains invalid characters' };
    }

    return { isValid: true };
  }

  /**
   * Validate phone number
   */
  static validatePhone(phone: string): { isValid: boolean; error?: string } {
    if (!phone) {
      return { isValid: false, error: 'Phone number is required' };
    }

    const sanitized = this.sanitizeInput(phone);
    
    if (sanitized.length > this.MAX_PHONE_LENGTH) {
      return { isValid: false, error: 'Phone number too long' };
    }

    // Allow digits, spaces, hyphens, parentheses, and plus sign
    const phoneRegex = /^[\d\s\-\(\)\+]+$/;
    if (!phoneRegex.test(sanitized)) {
      return { isValid: false, error: 'Phone number contains invalid characters' };
    }

    // Must have at least 7 digits
    const digitCount = sanitized.replace(/\D/g, '').length;
    if (digitCount < 7) {
      return { isValid: false, error: 'Phone number too short' };
    }

    return { isValid: true };
  }

  /**
   * Validate text fields (steps)
   */
  static validateTextInput(input: string, maxLength: number = 2000): { isValid: boolean; error?: string } {
    if (!input) {
      return { isValid: true }; // Optional fields
    }

    const sanitized = this.sanitizeInput(input);
    
    if (sanitized.length > maxLength) {
      return { isValid: false, error: `Text too long (max ${maxLength} characters)` };
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\s*\(/i,
      /document\./i,
      /window\./i,
      /(SELECT|INSERT|UPDATE|DELETE|DROP)\s/i,
      /union\s+select/i
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(sanitized)) {
        return { isValid: false, error: 'Input contains invalid content' };
      }
    }

    return { isValid: true };
  }

  /**
   * Rate limiting check (client-side)
   */
  static checkRateLimit(action: string, maxAttempts: number = 5, windowMs: number = 60000): boolean {
    const key = `rateLimit_${action}`;
    const now = Date.now();
    
    try {
      const stored = localStorage.getItem(key);
      const attempts = stored ? JSON.parse(stored) : [];
      
      // Filter out old attempts
      const recentAttempts = attempts.filter((timestamp: number) => now - timestamp < windowMs);
      
      if (recentAttempts.length >= maxAttempts) {
        return false; // Rate limit exceeded
      }
      
      // Add current attempt
      recentAttempts.push(now);
      localStorage.setItem(key, JSON.stringify(recentAttempts));
      
      return true;
    } catch (error) {
      console.error('Rate limit check failed:', error);
      return true; // Allow on error
    }
  }

  /**
   * Detect potential spam content
   */
  static detectSpam(text: string): boolean {
    const spamKeywords = [
      'viagra', 'casino', 'lottery', 'winner', 'congratulations',
      'click here', 'free money', 'make money fast', 'work from home',
      'weight loss', 'diet pills', 'enlargement'
    ];

    const lowercaseText = text.toLowerCase();
    const spamScore = spamKeywords.filter(keyword => lowercaseText.includes(keyword)).length;
    
    // Check for excessive repetition
    const repetitivePattern = /(.{3,})\1{3,}/;
    const hasRepetition = repetitivePattern.test(text);
    
    // Check for excessive caps
    const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
    const excessiveCaps = capsRatio > 0.7 && text.length > 10;
    
    return spamScore >= 2 || hasRepetition || excessiveCaps;
  }

  /**
   * Generate secure headers for API requests
   */
  static getSecureHeaders(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    };
  }

  /**
   * Secure session storage (avoid localStorage for sensitive data)
   */
  static setSecureStorage(key: string, value: string, expirationMinutes: number = 60): void {
    const item = {
      value,
      expiry: Date.now() + (expirationMinutes * 60 * 1000)
    };
    
    try {
      sessionStorage.setItem(key, JSON.stringify(item));
    } catch (error) {
      console.error('Failed to set secure storage:', error);
    }
  }

  static getSecureStorage(key: string): string | null {
    try {
      const item = sessionStorage.getItem(key);
      if (!item) return null;
      
      const parsed = JSON.parse(item);
      if (Date.now() > parsed.expiry) {
        sessionStorage.removeItem(key);
        return null;
      }
      
      return parsed.value;
    } catch (error) {
      console.error('Failed to get secure storage:', error);
      return null;
    }
  }

  /**
   * Clear all security-related storage
   */
  static clearSecureStorage(): void {
    try {
      sessionStorage.clear();
      // Only clear specific localStorage items to avoid breaking other app functionality
      const keysToRemove = Object.keys(localStorage).filter(key => 
        key.startsWith('rateLimit_') || key.startsWith('security_')
      );
      keysToRemove.forEach(key => localStorage.removeItem(key));
    } catch (error) {
      console.error('Failed to clear secure storage:', error);
    }
  }

  /**
   * Validate CSRF token (if implemented)
   */
  static getCSRFToken(): string | null {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  /**
   * Content Security Policy violation handler
   */
  static setupCSPReporting(): void {
    document.addEventListener('securitypolicyviolation', (event) => {
      console.error('CSP Violation:', {
        blockedURI: event.blockedURI,
        violatedDirective: event.violatedDirective,
        originalPolicy: event.originalPolicy,
        sourceFile: event.sourceFile,
        lineNumber: event.lineNumber
      });
      
      // Report to security monitoring endpoint
      fetch('/api/security/csp-violation/', {
        method: 'POST',
        headers: this.getSecureHeaders(),
        body: JSON.stringify({
          blockedURI: event.blockedURI,
          violatedDirective: event.violatedDirective,
          sourceFile: event.sourceFile,
          lineNumber: event.lineNumber
        })
      }).catch(error => console.error('Failed to report CSP violation:', error));
    });
  }
}