// src/components/form/ContactInfo.tsx - Professional contact form with enhanced styling
import React, { useState, useEffect, useRef } from 'react';
import { ChevronDown, Globe, Phone, Mail, User, Shield } from 'lucide-react';
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

interface ContactInfoProps {
  formData: FormData;
  onChange: (field: keyof FormData, value: string) => void;
}

const ContactInfo: React.FC<ContactInfoProps> = ({ formData, onChange }) => {
  const [selectedCountry, setSelectedCountry] = useState(countries.find(c => c.code === formData.country) || countries[0]);
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);
  const [countrySearch, setCountrySearch] = useState('');
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

  const handleCountrySelect = (country: Country) => {
    setSelectedCountry(country);
    setShowCountryDropdown(false);
    setCountrySearch('');
    onChange('country', country.code);
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
        
        {/* Phone Number */}
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
            
            {/* Phone Input */}
            <input
              type="tel"
              value={formData.phone}
              onChange={(e) => onChange('phone', e.target.value)}
              placeholder="Enter your phone number"
              className="flex-1 p-4 bg-white border-2 border-gray-200 rounded-r-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 shadow-sm hover:border-gray-300"
            />
          </div>
          
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>Selected: {selectedCountry.name} ({selectedCountry.prefix})</span>
            <span>For urgent matters and case updates</span>
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