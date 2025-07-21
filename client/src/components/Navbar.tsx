// src/components/Navbar.tsx - Conditional navbar with different styles for each page
import React from 'react';
import { ArrowLeft } from 'lucide-react';
import Logo from '../assets/logo.svg';

interface NavbarProps {
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

const Navbar: React.FC<NavbarProps> = ({ currentPage, setCurrentPage }) => {
  const isHomePage = currentPage === 'home';

  if (isHomePage) {
    // Transparent overlay navbar for home page
    return (
      <nav className="absolute top-0 left-0 right-0 z-50 bg-transparent">
        <div className="max-w-7xl mx-auto px-5">
          <div className="flex justify-start items-center h-20">
            <div className="flex-shrink-0 flex items-center">
              <img 
                src={Logo} 
                alt="FormSite Logo" 
                className="h-16 w-auto opacity-90 hover:opacity-100 transition-opacity duration-300" 
              />
            </div>
          </div>
        </div>
      </nav>
    );
  }

  // Solid navbar for other pages (like request page)
  return (
    <nav className="bg-gray-900 shadow-lg border-b border-gray-700 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <img 
                src={Logo} 
                alt="FormSite Logo" 
                className="h-12 w-auto filter brightness-110" 
              />
            </div>
          </div>

          {/* Back to Home Button */}
          <div className="flex items-center">
            <button
              onClick={() => setCurrentPage('home')}
              className="flex items-center space-x-2 px-4 py-2 text-gray-300 hover:text-white transition-colors duration-200 font-medium"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Home</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar; 