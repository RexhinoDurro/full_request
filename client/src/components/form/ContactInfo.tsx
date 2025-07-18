// client/src/components/form/ContactInfo.tsx - COMPLETE VERSION with enhanced phone validation
import React, { useState, useEffect, useRef } from 'react';
import { ChevronDown, Globe, Phone, Mail, User, Shield, AlertCircle, CheckCircle } from 'lucide-react';
import type { FormData, Country } from '../../types/form';

const countries: Country[] = [
  // Americas
  { code: 'US', name: 'United States', flag: '🇺🇸', prefix: '+1' },
  { code: 'CA', name: 'Canada', flag: '🇨🇦', prefix: '+1' },
  { code: 'MX', name: 'Mexico', flag: '🇲🇽', prefix: '+52' },
  { code: 'BR', name: 'Brazil', flag: '🇧🇷', prefix: '+55' },
  { code: 'AR', name: 'Argentina', flag: '🇦🇷', prefix: '+54' },
  { code: 'CL', name: 'Chile', flag: '🇨🇱', prefix: '+56' },
  { code: 'CO', name: 'Colombia', flag: '🇨🇴', prefix: '+57' },
  { code: 'PE', name: 'Peru', flag: '🇵🇪', prefix: '+51' },
  { code: 'VE', name: 'Venezuela', flag: '🇻🇪', prefix: '+58' },
  { code: 'EC', name: 'Ecuador', flag: '🇪🇨', prefix: '+593' },
  
  // Europe
  { code: 'GB', name: 'United Kingdom', flag: '🇬🇧', prefix: '+44' },
  { code: 'DE', name: 'Germany', flag: '🇩🇪', prefix: '+49' },
  { code: 'FR', name: 'France', flag: '🇫🇷', prefix: '+33' },
  { code: 'IT', name: 'Italy', flag: '🇮🇹', prefix: '+39' },
  { code: 'ES', name: 'Spain', flag: '🇪🇸', prefix: '+34' },
  { code: 'NL', name: 'Netherlands', flag: '🇳🇱', prefix: '+31' },
  { code: 'BE', name: 'Belgium', flag: '🇧🇪', prefix: '+32' },
  { code: 'CH', name: 'Switzerland', flag: '🇨🇭', prefix: '+41' },
  { code: 'AT', name: 'Austria', flag: '🇦🇹', prefix: '+43' },
  { code: 'SE', name: 'Sweden', flag: '🇸🇪', prefix: '+46' },
  { code: 'NO', name: 'Norway', flag: '🇳🇴', prefix: '+47' },
  { code: 'DK', name: 'Denmark', flag: '🇩🇰', prefix: '+45' },
  { code: 'FI', name: 'Finland', flag: '🇫🇮', prefix: '+358' },
  { code: 'IE', name: 'Ireland', flag: '🇮🇪', prefix: '+353' },
  { code: 'PT', name: 'Portugal', flag: '🇵🇹', prefix: '+351' },
  
  // Asia
  { code: 'CN', name: 'China', flag: '🇨🇳', prefix: '+86' },
  { code: 'JP', name: 'Japan', flag: '🇯🇵', prefix: '+81' },
  { code: 'KR', name: 'South Korea', flag: '🇰🇷', prefix: '+82' },
  { code: 'IN', name: 'India', flag: '🇮🇳', prefix: '+91' },
  { code: 'ID', name: 'Indonesia', flag: '🇮🇩', prefix: '+62' },
  { code: 'TH', name: 'Thailand', flag: '🇹🇭', prefix: '+66' },
  { code: 'VN', name: 'Vietnam', flag: '🇻🇳', prefix: '+84' },
  { code: 'PH', name: 'Philippines', flag: '🇵🇭', prefix: '+63' },
  { code: 'MY', name: 'Malaysia', flag: '🇲🇾', prefix: '+60' },
  { code: 'SG', name: 'Singapore', flag: '🇸🇬', prefix: '+65' },
  
  // Middle East
  { code: 'AE', name: 'United Arab Emirates', flag: '🇦🇪', prefix: '+971' },
  { code: 'SA', name: 'Saudi Arabia', flag: '🇸🇦', prefix: '+966' },
  { code: 'QA', name: 'Qatar', flag: '🇶🇦', prefix: '+974' },
  { code: 'KW', name: 'Kuwait', flag: '🇰🇼', prefix: '+965' },
  { code: 'BH', name: 'Bahrain', flag: '🇧🇭', prefix: '+973' },
  { code: 'OM', name: 'Oman', flag: '🇴🇲', prefix: '+968' },
  { code: 'JO', name: 'Jordan', flag: '🇯🇴', prefix: '+962' },
  { code: 'LB', name: 'Lebanon', flag: '🇱🇧', prefix: '+961' },
  { code: 'IL', name: 'Israel', flag: '🇮🇱', prefix: '+972' },
  { code: 'TR', name: 'Turkey', flag: '🇹🇷', prefix: '+90' },
  
  // Africa
  { code: 'ZA', name: 'South Africa', flag: '🇿🇦', prefix: '+27' },
  { code: 'EG', name: 'Egypt', flag: '🇪🇬', prefix: '+20' },
  { code: 'NG', name: 'Nigeria', flag: '🇳🇬', prefix: '+234' },
  { code: 'KE', name: 'Kenya', flag: '🇰🇪', prefix: '+254' },
  { code: 'GH', name: 'Ghana', flag: '🇬🇭', prefix: '+233' },
  { code: 'MA', name: 'Morocco', flag: '🇲🇦', prefix: '+212' },
  
  // Oceania
  { code: 'AU', name: 'Australia', flag: '🇦🇺', prefix: '+61' },
  { code: 'NZ', name: 'New Zealand', flag: '🇳🇿', prefix: '+64' },
].sort((a, b) => a.name.localeCompare(b.name));

// Enhanced phone validation function
const validatePhoneNumber = (phone: string, countryCode: string): { isValid: boolean; error?: string; formatted?: string } => {
  if (!phone) {
    return { isValid: false, error: 'Phone number is required' };
  }

  // Remove all non-digit characters except + for initial cleaning
  const cleaned = phone.replace(/[^\d\+]/g, '');
  
  // Check if phone is too short or too long
  if (cleaned.length < 7) {
    return { isValid: false, error: 'Phone number is too short (minimum 7 digits)' };
  }
  
  if (cleaned.length > 15) {
    return { isValid: false, error: 'Phone number is too long (maximum 15 digits)' };
  }

  // Country-specific validation patterns
  const phonePatterns: Record<string, { pattern: RegExp; format: string; example: string }> = {
    'US': { 
      pattern: /^(\+1)?[2-9]\d{2}[2-9]\d{2}\d{4}$/, 
      format: '+1 (XXX) XXX-XXXX',
      example: '+1 (555) 123-4567'
    },
    'CA': { 
      pattern: /^(\+1)?[2-9]\d{2}[2-9]\d{2}\d{4}$/, 
      format: '+1 (XXX) XXX-XXXX',
      example: '+1 (416) 555-1234'
    },
    'GB': { 
      pattern: /^(\+44)?[1-9]\d{8,9}$/, 
      format: '+44 XXXX XXXXXX',
      example: '+44 20 7946 0958'
    },
    'DE': { 
      pattern: /^(\+49)?[1-9]\d{10,11}$/, 
      format: '+49 XXX XXXXXXXX',
      example: '+49 30 12345678'
    },
    'FR': { 
      pattern: /^(\+33)?[1-9]\d{8}$/, 
      format: '+33 X XX XX XX XX',
      example: '+33 1 42 34 56 78'
    },
    'AU': { 
      pattern: /^(\+61)?[2-9]\d{8}$/, 
      format: '+61 X XXXX XXXX',
      example: '+61 2 9876 5432'
    },
    'JP': { 
      pattern: /^(\+81)?[1-9]\d{9,10}$/, 
      format: '+81 XX XXXX XXXX',
      example: '+81 3 1234 5678'
    },
    'IN': { 
      pattern: /^(\+91)?[6-9]\d{9}$/, 
      format: '+91 XXXXX XXXXX',
      example: '+91 98765 43210'
    },
  };

  const countryPattern = phonePatterns[countryCode];
  
  if (countryPattern) {
    // Test against country-specific pattern
    const digitsOnly = cleaned.replace(/^\+\d{1,3}/, ''); // Remove country code for testing
    const withCountryCode = cleaned.startsWith('+') ? cleaned : `+${getCountryDialCode(countryCode)}${digitsOnly}`;
    
    if (!countryPattern.pattern.test(withCountryCode.replace(/[^\d\+]/g, ''))) {
      return { 
        isValid: false, 
        error: `Invalid ${getCountryName(countryCode)} phone number. Expected format: ${countryPattern.format}. Example: ${countryPattern.example}` 
      };
    }
    
    return { 
      isValid: true, 
      formatted: formatPhoneNumber(withCountryCode, countryCode)
    };
  } else {
    // Generic international validation for other countries
    const internationalPattern = /^\+\d{7,15}$/;
    const withPlus = cleaned.startsWith('+') ? cleaned : `+${getCountryDialCode(countryCode)}${cleaned}`;
    
    if (!internationalPattern.test(withPlus)) {
      return { 
        isValid: false, 
        error: `Invalid phone number. Please use international format: +${getCountryDialCode(countryCode)} followed by your number` 
      };
    }
    
    return { 
      isValid: true, 
      formatted: withPlus
    };
  }
};

// Helper functions
const getCountryDialCode = (countryCode: string): string => {
  const country = countries.find(c => c.code === countryCode);
  return country?.prefix.replace('+', '') || '1';
};

const getCountryName = (countryCode: string): string => {
  const countryNames: Record<string, string> = {
    'US': 'US', 'CA': 'Canadian', 'GB': 'UK', 'DE': 'German', 'FR': 'French',
    'AU': 'Australian', 'JP': 'Japanese', 'IN': 'Indian'
  };
  return countryNames[countryCode] || 'International';
};

const formatPhoneNumber = (phone: string, countryCode: string): string => {
  const cleaned = phone.replace(/[^\d\+]/g, '');
  
  // Country-specific formatting
  if (countryCode === 'US' || countryCode === 'CA') {
    const match = cleaned.match(/^(\+1)?(\d{3})(\d{3})(\d{4})$/);
    if (match) {
      return `+1 (${match[2]}) ${match[3]}-${match[4]}`;
    }
  }
  
  // Default: just ensure it starts with country code
  if (!cleaned.startsWith('+')) {
    return `+${getCountryDialCode(countryCode)}${cleaned}`;
  }
  
  return cleaned;
};

interface ContactInfoProps {
  formData: FormData;
  onChange: (field: keyof FormData, value: string) => void;
}

const ContactInfo: React.FC<ContactInfoProps> = ({ formData, onChange }) => {
  const [selectedCountry, setSelectedCountry] = useState(countries.find(c => c.code === formData.country) || countries[0]);
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);
  const [countrySearch, setCountrySearch] = useState('');
  const [phoneValidation, setPhoneValidation] = useState<{ isValid: boolean; error?: string; formatted?: string }>({ isValid: true });
  const dropdownRef = useRef<HTMLDivElement>(null);

  const filteredCountries = countries.filter(country =>
    country.name.toLowerCase().includes(countrySearch.toLowerCase()) ||
    country.prefix.includes(countrySearch)
  );

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowCountryDropdown(false);
        setCountrySearch('');
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  useEffect(() => {
    if (!formData.country) {
      onChange('country', selectedCountry.code);
    }
  }, []);

  // Enhanced phone change handler
  const handlePhoneChange = (value: string) => {
    // Real-time validation
    const validation = validatePhoneNumber(value, selectedCountry.code);
    setPhoneValidation(validation);
    
    // Update form data
    onChange('phone', value);
  };

  const handleCountrySelect = (country: Country) => {
    setSelectedCountry(country);
    setShowCountryDropdown(false);
    setCountrySearch('');
    onChange('country', country.code);
    
    // Re-validate phone number with new country
    if (formData.phone) {
      const validation = validatePhoneNumber(formData.phone, country.code);
      setPhoneValidation(validation);
    }
  };

  return (
    <div className="space-y-8">
      <div className="text-center space-y-3">
        <h3 className="text-2xl font-semibold text-gray-900">Contact Information</h3>
        <p className="text-gray-600">
          Please provide your contact details so our team can reach out to you with updates on your application.
        </p>
        
        {/* Security Notice */}
        <div className="inline-flex items-center space-x-2 px-4 py-2 bg-green-50 rounded-lg border border-green-200">
          <Shield className="w-4 h-4 text-green-600" />
          <span className="text-sm font-medium text-green-800">All information is encrypted and secure</span>
        </div>
      </div>
      
      <div className="space-y-6">
        {/* Full Name */}
        <div className="space-y-2">
          <label className="flex items-center space-x-2 text-gray-700 font-medium">
            <User className="w-4 h-4 text-gray-500" />
            <span>Full Name *</span>
          </label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => onChange('name', e.target.value)}
            placeholder="Enter your full name"
            className="w-full p-4 bg-white border-2 border-gray-200 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 shadow-sm hover:border-gray-300"
          />
        </div>
        
        {/* Email Address */}
        <div className="space-y-2">
          <label className="flex items-center space-x-2 text-gray-700 font-medium">
            <Mail className="w-4 h-4 text-gray-500" />
            <span>Email Address *</span>
          </label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => onChange('email', e.target.value)}
            placeholder="your.email@example.com"
            className="w-full p-4 bg-white border-2 border-gray-200 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 shadow-sm hover:border-gray-300"
          />
          <p className="text-xs text-gray-500">We'll use this email to send you updates about your application</p>
        </div>
        
        {/* Enhanced Phone Number Section */}
        <div className="space-y-2">
          <label className="flex items-center space-x-2 text-gray-700 font-medium">
            <Phone className="w-4 h-4 text-gray-500" />
            <span>Phone Number *</span>
          </label>
          
          <div className="flex">
            {/* Country Selector */}
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setShowCountryDropdown(!showCountryDropdown)}
                className="flex items-center space-x-3 px-4 py-4 bg-white border-2 border-gray-200 border-r-0 rounded-l-xl text-gray-900 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all duration-200 shadow-sm hover:border-gray-300 min-w-[140px]"
              >
                <span className="text-lg">{selectedCountry.flag}</span>
                <span className="text-sm font-medium">{selectedCountry.prefix}</span>
                <ChevronDown className="w-4 h-4 text-gray-400" />
              </button>
              
              {showCountryDropdown && (
                <div className="absolute top-full left-0 mt-1 w-80 bg-white border-2 border-gray-200 rounded-xl shadow-xl z-20 max-h-64 overflow-hidden">
                  <div className="p-3 border-b border-gray-200">
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <input
                        type="text"
                        placeholder="Search countries..."
                        value={countrySearch}
                        onChange={(e) => setCountrySearch(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
                        autoFocus
                      />
                    </div>
                  </div>
                  <div className="overflow-y-auto max-h-48">
                    {filteredCountries.map((country) => (
                      <button
                        key={country.code}
                        onClick={() => handleCountrySelect(country)}
                        className="w-full flex items-center space-x-3 px-4 py-3 text-left hover:bg-purple-50 transition-colors duration-200 text-gray-800"
                      >
                        <span className="text-lg">{country.flag}</span>
                        <span className="font-medium text-sm min-w-[50px]">{country.prefix}</span>
                        <span className="text-sm flex-1">{country.name}</span>
                      </button>
                    ))}
                    {filteredCountries.length === 0 && (
                      <div className="p-4 text-center text-gray-500 text-sm">
                        No countries found
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* Enhanced Phone Input */}
            <div className="flex-1 relative">
              <input
                type="tel"
                value={formData.phone}
                onChange={(e) => handlePhoneChange(e.target.value)}
                placeholder="Enter your phone number"
                className={`w-full p-4 bg-white border-2 rounded-r-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 transition-all duration-200 shadow-sm pr-12 ${
                  phoneValidation.isValid 
                    ? 'border-gray-200 focus:ring-purple-500 focus:border-transparent hover:border-gray-300' 
                    : 'border-red-300 focus:ring-red-500 focus:border-red-500'
                }`}
              />
              
              {/* Validation Icon */}
              {formData.phone && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                  {phoneValidation.isValid ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <AlertCircle className="w-5 h-5 text-red-500" />
                  )}
                </div>
              )}
            </div>
          </div>
          
          {/* Enhanced Validation Messages */}
          <div className="text-xs space-y-1">
            <div className="flex items-center justify-between text-gray-500">
              <span>Selected: {selectedCountry.name} ({selectedCountry.prefix})</span>
              <span>For urgent matters and case updates</span>
            </div>
            
            {!phoneValidation.isValid && phoneValidation.error && (
              <div className="flex items-center space-x-2 text-red-600 bg-red-50 px-3 py-2 rounded-lg">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{phoneValidation.error}</span>
              </div>
            )}
            
            {phoneValidation.isValid && formData.phone && phoneValidation.formatted && (
              <div className="flex items-center space-x-2 text-green-600 bg-green-50 px-3 py-2 rounded-lg">
                <CheckCircle className="w-4 h-4 flex-shrink-0" />
                <span>Formatted: {phoneValidation.formatted}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Privacy Notice */}
      <div className="bg-gray-50 rounded-xl p-6 border border-gray-200">
        <h4 className="font-semibold text-gray-900 mb-3">Privacy & Data Protection</h4>
        <div className="space-y-2 text-sm text-gray-600">
          <p>• Your information is encrypted using industry-standard security protocols</p>
          <p>• We never share your personal data with third parties without consent</p>
          <p>• All communications are confidential and protected by our privacy policy</p>
          <p>• You can request deletion of your data at any time</p>
        </div>
      </div>
    </div>
  );
};

export default ContactInfo;