// ===========================
// src/components/form/ContactInfo.tsx - Contact form with country selector
// ===========================

import React, { useState } from 'react';
import type { FormData, Country } from '../../types/form';

const countries: Country[] = [
  { code: 'US', name: 'United States', flag: '🇺🇸', prefix: '+1' },
  { code: 'GB', name: 'United Kingdom', flag: '🇬🇧', prefix: '+44' },
  { code: 'CA', name: 'Canada', flag: '🇨🇦', prefix: '+1' },
  { code: 'AU', name: 'Australia', flag: '🇦🇺', prefix: '+61' },
  { code: 'DE', name: 'Germany', flag: '🇩🇪', prefix: '+49' },
  { code: 'FR', name: 'France', flag: '🇫🇷', prefix: '+33' },
  { code: 'JP', name: 'Japan', flag: '🇯🇵', prefix: '+81' },
  { code: 'IN', name: 'India', flag: '🇮🇳', prefix: '+91' },
];

interface ContactInfoProps {
  formData: FormData;
  onChange: (field: keyof FormData, value: string) => void;
}

const ContactInfo: React.FC<ContactInfoProps> = ({ formData, onChange }) => {
  const [selectedCountry, setSelectedCountry] = useState(countries[0]);
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);

  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-semibold text-gray-800">Please provide your contact information</h3>
      
      <div className="space-y-6">
        <div>
          <label className="block text-gray-700 font-medium mb-2">What is your name?</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => onChange('name', e.target.value)}
            placeholder="Your name"
            className="w-full p-4 bg-white border-2 border-gray-300 rounded-xl text-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
          />
        </div>
        
        <div>
          <label className="block text-gray-700 font-medium mb-2">Your Email</label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => onChange('email', e.target.value)}
            placeholder="Your Email"
            className="w-full p-4 bg-white border-2 border-gray-300 rounded-xl text-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
          />
        </div>
        
        <div>
          <label className="block text-gray-700 font-medium mb-2">Your phone number</label>
          <div className="flex">
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowCountryDropdown(!showCountryDropdown)}
                className="flex items-center space-x-2 px-4 py-4 bg-white border-2 border-gray-300 border-r-0 rounded-l-xl text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 shadow-sm"
              >
                <span className="text-lg">{selectedCountry.flag}</span>
                <span>{selectedCountry.prefix}</span>
              </button>
              
              {showCountryDropdown && (
                <div className="absolute top-full left-0 mt-1 w-64 bg-white border-2 border-gray-300 rounded-xl shadow-lg z-10 max-h-48 overflow-y-auto">
                  {countries.map((country) => (
                    <button
                      key={country.code}
                      onClick={() => {
                        setSelectedCountry(country);
                        setShowCountryDropdown(false);
                        onChange('country', country.code);
                      }}
                      className="w-full flex items-center space-x-3 px-4 py-3 text-left hover:bg-blue-50 transition-colors duration-200 text-gray-800"
                    >
                      <span className="text-lg">{country.flag}</span>
                      <span className="font-medium">{country.prefix}</span>
                      <span>{country.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            
            <input
              type="tel"
              value={formData.phone}
              onChange={(e) => onChange('phone', e.target.value)}
              placeholder="Phone number"
              className="flex-1 p-4 bg-white border-2 border-gray-300 rounded-r-xl text-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContactInfo;