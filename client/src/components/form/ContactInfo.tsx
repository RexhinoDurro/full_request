// ===========================
// src/components/form/ContactInfo.tsx - Contact form with comprehensive country selector
// ===========================

import React, { useState, useEffect, useRef } from 'react';
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
  { code: 'UY', name: 'Uruguay', flag: '🇺🇾', prefix: '+598' },
  { code: 'PY', name: 'Paraguay', flag: '🇵🇾', prefix: '+595' },
  { code: 'BO', name: 'Bolivia', flag: '🇧🇴', prefix: '+591' },
  { code: 'CR', name: 'Costa Rica', flag: '🇨🇷', prefix: '+506' },
  { code: 'PA', name: 'Panama', flag: '🇵🇦', prefix: '+507' },
  { code: 'GT', name: 'Guatemala', flag: '🇬🇹', prefix: '+502' },
  { code: 'HN', name: 'Honduras', flag: '🇭🇳', prefix: '+504' },
  { code: 'SV', name: 'El Salvador', flag: '🇸🇻', prefix: '+503' },
  { code: 'NI', name: 'Nicaragua', flag: '🇳🇮', prefix: '+505' },
  { code: 'BZ', name: 'Belize', flag: '🇧🇿', prefix: '+501' },
  { code: 'JM', name: 'Jamaica', flag: '🇯🇲', prefix: '+1876' },
  { code: 'CU', name: 'Cuba', flag: '🇨🇺', prefix: '+53' },
  { code: 'DO', name: 'Dominican Republic', flag: '🇩🇴', prefix: '+1849' },
  { code: 'HT', name: 'Haiti', flag: '🇭🇹', prefix: '+509' },
  { code: 'TT', name: 'Trinidad and Tobago', flag: '🇹🇹', prefix: '+1868' },

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
  { code: 'PL', name: 'Poland', flag: '🇵🇱', prefix: '+48' },
  { code: 'CZ', name: 'Czech Republic', flag: '🇨🇿', prefix: '+420' },
  { code: 'HU', name: 'Hungary', flag: '🇭🇺', prefix: '+36' },
  { code: 'SK', name: 'Slovakia', flag: '🇸🇰', prefix: '+421' },
  { code: 'SI', name: 'Slovenia', flag: '🇸🇮', prefix: '+386' },
  { code: 'HR', name: 'Croatia', flag: '🇭🇷', prefix: '+385' },
  { code: 'RO', name: 'Romania', flag: '🇷🇴', prefix: '+40' },
  { code: 'BG', name: 'Bulgaria', flag: '🇧🇬', prefix: '+359' },
  { code: 'GR', name: 'Greece', flag: '🇬🇷', prefix: '+30' },
  { code: 'CY', name: 'Cyprus', flag: '🇨🇾', prefix: '+357' },
  { code: 'MT', name: 'Malta', flag: '🇲🇹', prefix: '+356' },
  { code: 'LU', name: 'Luxembourg', flag: '🇱🇺', prefix: '+352' },
  { code: 'EE', name: 'Estonia', flag: '🇪🇪', prefix: '+372' },
  { code: 'LV', name: 'Latvia', flag: '🇱🇻', prefix: '+371' },
  { code: 'LT', name: 'Lithuania', flag: '🇱🇹', prefix: '+370' },
  { code: 'AL', name: 'Albania', flag: '🇦🇱', prefix: '+355' },
  { code: 'BA', name: 'Bosnia and Herzegovina', flag: '🇧🇦', prefix: '+387' },
  { code: 'ME', name: 'Montenegro', flag: '🇲🇪', prefix: '+382' },
  { code: 'MK', name: 'North Macedonia', flag: '🇲🇰', prefix: '+389' },
  { code: 'RS', name: 'Serbia', flag: '🇷🇸', prefix: '+381' },
  { code: 'RU', name: 'Russia', flag: '🇷🇺', prefix: '+7' },
  { code: 'UA', name: 'Ukraine', flag: '🇺🇦', prefix: '+380' },
  { code: 'BY', name: 'Belarus', flag: '🇧🇾', prefix: '+375' },
  { code: 'MD', name: 'Moldova', flag: '🇲🇩', prefix: '+373' },
  { code: 'IS', name: 'Iceland', flag: '🇮🇸', prefix: '+354' },

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
  { code: 'TW', name: 'Taiwan', flag: '🇹🇼', prefix: '+886' },
  { code: 'HK', name: 'Hong Kong', flag: '🇭🇰', prefix: '+852' },
  { code: 'MO', name: 'Macau', flag: '🇲🇴', prefix: '+853' },
  { code: 'MM', name: 'Myanmar', flag: '🇲🇲', prefix: '+95' },
  { code: 'KH', name: 'Cambodia', flag: '🇰🇭', prefix: '+855' },
  { code: 'LA', name: 'Laos', flag: '🇱🇦', prefix: '+856' },
  { code: 'BD', name: 'Bangladesh', flag: '🇧🇩', prefix: '+880' },
  { code: 'LK', name: 'Sri Lanka', flag: '🇱🇰', prefix: '+94' },
  { code: 'PK', name: 'Pakistan', flag: '🇵🇰', prefix: '+92' },
  { code: 'AF', name: 'Afghanistan', flag: '🇦🇫', prefix: '+93' },
  { code: 'NP', name: 'Nepal', flag: '🇳🇵', prefix: '+977' },
  { code: 'BT', name: 'Bhutan', flag: '🇧🇹', prefix: '+975' },
  { code: 'MV', name: 'Maldives', flag: '🇲🇻', prefix: '+960' },
  { code: 'UZ', name: 'Uzbekistan', flag: '🇺🇿', prefix: '+998' },
  { code: 'KZ', name: 'Kazakhstan', flag: '🇰🇿', prefix: '+7' },
  { code: 'KG', name: 'Kyrgyzstan', flag: '🇰🇬', prefix: '+996' },
  { code: 'TJ', name: 'Tajikistan', flag: '🇹🇯', prefix: '+992' },
  { code: 'TM', name: 'Turkmenistan', flag: '🇹🇲', prefix: '+993' },
  { code: 'MN', name: 'Mongolia', flag: '🇲🇳', prefix: '+976' },

  // Middle East
  { code: 'AE', name: 'United Arab Emirates', flag: '🇦🇪', prefix: '+971' },
  { code: 'SA', name: 'Saudi Arabia', flag: '🇸🇦', prefix: '+966' },
  { code: 'QA', name: 'Qatar', flag: '🇶🇦', prefix: '+974' },
  { code: 'KW', name: 'Kuwait', flag: '🇰🇼', prefix: '+965' },
  { code: 'BH', name: 'Bahrain', flag: '🇧🇭', prefix: '+973' },
  { code: 'OM', name: 'Oman', flag: '🇴🇲', prefix: '+968' },
  { code: 'JO', name: 'Jordan', flag: '🇯🇴', prefix: '+962' },
  { code: 'LB', name: 'Lebanon', flag: '🇱🇧', prefix: '+961' },
  { code: 'SY', name: 'Syria', flag: '🇸🇾', prefix: '+963' },
  { code: 'IQ', name: 'Iraq', flag: '🇮🇶', prefix: '+964' },
  { code: 'IR', name: 'Iran', flag: '🇮🇷', prefix: '+98' },
  { code: 'IL', name: 'Israel', flag: '🇮🇱', prefix: '+972' },
  { code: 'PS', name: 'Palestine', flag: '🇵🇸', prefix: '+970' },
  { code: 'TR', name: 'Turkey', flag: '🇹🇷', prefix: '+90' },
  { code: 'YE', name: 'Yemen', flag: '🇾🇪', prefix: '+967' },

  // Africa
  { code: 'ZA', name: 'South Africa', flag: '🇿🇦', prefix: '+27' },
  { code: 'EG', name: 'Egypt', flag: '🇪🇬', prefix: '+20' },
  { code: 'NG', name: 'Nigeria', flag: '🇳🇬', prefix: '+234' },
  { code: 'KE', name: 'Kenya', flag: '🇰🇪', prefix: '+254' },
  { code: 'GH', name: 'Ghana', flag: '🇬🇭', prefix: '+233' },
  { code: 'ET', name: 'Ethiopia', flag: '🇪🇹', prefix: '+251' },
  { code: 'TZ', name: 'Tanzania', flag: '🇹🇿', prefix: '+255' },
  { code: 'UG', name: 'Uganda', flag: '🇺🇬', prefix: '+256' },
  { code: 'MA', name: 'Morocco', flag: '🇲🇦', prefix: '+212' },
  { code: 'DZ', name: 'Algeria', flag: '🇩🇿', prefix: '+213' },
  { code: 'TN', name: 'Tunisia', flag: '🇹🇳', prefix: '+216' },
  { code: 'LY', name: 'Libya', flag: '🇱🇾', prefix: '+218' },
  { code: 'SD', name: 'Sudan', flag: '🇸🇩', prefix: '+249' },
  { code: 'SS', name: 'South Sudan', flag: '🇸🇸', prefix: '+211' },
  { code: 'ZW', name: 'Zimbabwe', flag: '🇿🇼', prefix: '+263' },
  { code: 'ZM', name: 'Zambia', flag: '🇿🇲', prefix: '+260' },
  { code: 'BW', name: 'Botswana', flag: '🇧🇼', prefix: '+267' },
  { code: 'NA', name: 'Namibia', flag: '🇳🇦', prefix: '+264' },
  { code: 'MZ', name: 'Mozambique', flag: '🇲🇿', prefix: '+258' },
  { code: 'MW', name: 'Malawi', flag: '🇲🇼', prefix: '+265' },
  { code: 'SZ', name: 'Eswatini', flag: '🇸🇿', prefix: '+268' },
  { code: 'LS', name: 'Lesotho', flag: '🇱🇸', prefix: '+266' },
  { code: 'RW', name: 'Rwanda', flag: '🇷🇼', prefix: '+250' },
  { code: 'BI', name: 'Burundi', flag: '🇧🇮', prefix: '+257' },
  { code: 'DJ', name: 'Djibouti', flag: '🇩🇯', prefix: '+253' },
  { code: 'SO', name: 'Somalia', flag: '🇸🇴', prefix: '+252' },
  { code: 'ER', name: 'Eritrea', flag: '🇪🇷', prefix: '+291' },
  { code: 'AO', name: 'Angola', flag: '🇦🇴', prefix: '+244' },
  { code: 'CD', name: 'Democratic Republic of Congo', flag: '🇨🇩', prefix: '+243' },
  { code: 'CG', name: 'Republic of Congo', flag: '🇨🇬', prefix: '+242' },
  { code: 'CF', name: 'Central African Republic', flag: '🇨🇫', prefix: '+236' },
  { code: 'CM', name: 'Cameroon', flag: '🇨🇲', prefix: '+237' },
  { code: 'TD', name: 'Chad', flag: '🇹🇩', prefix: '+235' },
  { code: 'GA', name: 'Gabon', flag: '🇬🇦', prefix: '+241' },
  { code: 'GQ', name: 'Equatorial Guinea', flag: '🇬🇶', prefix: '+240' },
  { code: 'ST', name: 'São Tomé and Príncipe', flag: '🇸🇹', prefix: '+239' },
  { code: 'CI', name: 'Côte d\'Ivoire', flag: '🇨🇮', prefix: '+225' },
  { code: 'LR', name: 'Liberia', flag: '🇱🇷', prefix: '+231' },
  { code: 'SL', name: 'Sierra Leone', flag: '🇸🇱', prefix: '+232' },
  { code: 'GN', name: 'Guinea', flag: '🇬🇳', prefix: '+224' },
  { code: 'GW', name: 'Guinea-Bissau', flag: '🇬🇼', prefix: '+245' },
  { code: 'SN', name: 'Senegal', flag: '🇸🇳', prefix: '+221' },
  { code: 'GM', name: 'Gambia', flag: '🇬🇲', prefix: '+220' },
  { code: 'ML', name: 'Mali', flag: '🇲🇱', prefix: '+223' },
  { code: 'BF', name: 'Burkina Faso', flag: '🇧🇫', prefix: '+226' },
  { code: 'NE', name: 'Niger', flag: '🇳🇪', prefix: '+227' },
  { code: 'MR', name: 'Mauritania', flag: '🇲🇷', prefix: '+222' },
  { code: 'CV', name: 'Cape Verde', flag: '🇨🇻', prefix: '+238' },
  { code: 'MU', name: 'Mauritius', flag: '🇲🇺', prefix: '+230' },
  { code: 'SC', name: 'Seychelles', flag: '🇸🇨', prefix: '+248' },
  { code: 'MG', name: 'Madagascar', flag: '🇲🇬', prefix: '+261' },
  { code: 'KM', name: 'Comoros', flag: '🇰🇲', prefix: '+269' },

  // Oceania
  { code: 'AU', name: 'Australia', flag: '🇦🇺', prefix: '+61' },
  { code: 'NZ', name: 'New Zealand', flag: '🇳🇿', prefix: '+64' },
  { code: 'FJ', name: 'Fiji', flag: '🇫🇯', prefix: '+679' },
  { code: 'PG', name: 'Papua New Guinea', flag: '🇵🇬', prefix: '+675' },
  { code: 'NC', name: 'New Caledonia', flag: '🇳🇨', prefix: '+687' },
  { code: 'SB', name: 'Solomon Islands', flag: '🇸🇧', prefix: '+677' },
  { code: 'VU', name: 'Vanuatu', flag: '🇻🇺', prefix: '+678' },
  { code: 'WS', name: 'Samoa', flag: '🇼🇸', prefix: '+685' },
  { code: 'TO', name: 'Tonga', flag: '🇹🇴', prefix: '+676' },
  { code: 'KI', name: 'Kiribati', flag: '🇰🇮', prefix: '+686' },
  { code: 'TV', name: 'Tuvalu', flag: '🇹🇻', prefix: '+688' },
  { code: 'NR', name: 'Nauru', flag: '🇳🇷', prefix: '+674' },
  { code: 'PW', name: 'Palau', flag: '🇵🇼', prefix: '+680' },
  { code: 'FM', name: 'Micronesia', flag: '🇫🇲', prefix: '+691' },
  { code: 'MH', name: 'Marshall Islands', flag: '🇲🇭', prefix: '+692' },
].sort((a, b) => a.name.localeCompare(b.name)); // Sort alphabetically by country name

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

  // Close dropdown when clicking outside
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

  // Initialize with default country if not set
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
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setShowCountryDropdown(!showCountryDropdown)}
                className="flex items-center space-x-2 px-4 py-4 bg-white border-2 border-gray-300 border-r-0 rounded-l-xl text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 shadow-sm min-w-[120px]"
              >
                <span className="text-lg">{selectedCountry.flag}</span>
                <span className="text-sm font-medium">{selectedCountry.prefix}</span>
                <svg className="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showCountryDropdown && (
                <div className="absolute top-full left-0 mt-1 w-80 bg-white border-2 border-gray-300 rounded-xl shadow-lg z-20 max-h-64 overflow-hidden">
                  <div className="p-3 border-b border-gray-200">
                    <input
                      type="text"
                      placeholder="Search countries..."
                      value={countrySearch}
                      onChange={(e) => setCountrySearch(e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg text-sm"
                      autoFocus
                    />
                  </div>
                  <div className="overflow-y-auto max-h-48">
                    {filteredCountries.map((country) => (
                      <button
                        key={country.code}
                        onClick={() => handleCountrySelect(country)}
                        className="w-full flex items-center space-x-3 px-4 py-3 text-left hover:bg-blue-50 transition-colors duration-200 text-gray-800"
                      >
                        <span className="text-lg">{country.flag}</span>
                        <span className="font-medium text-sm">{country.prefix}</span>
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
            
            <input
              type="tel"
              value={formData.phone}
              onChange={(e) => onChange('phone', e.target.value)}
              placeholder="Phone number"
              className="flex-1 p-4 bg-white border-2 border-gray-300 rounded-r-xl text-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
            />
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Selected: {selectedCountry.name} ({selectedCountry.prefix})
          </p>
        </div>
      </div>
    </div>
  );
};

export default ContactInfo;