// src/components/Navbar.tsx - Navigation component with imported logo
import React from 'react';
import Logo from '../assets/logo.svg'; // Import your logo from assets

interface NavbarProps {
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

const Navbar: React.FC<NavbarProps> = ({ currentPage, setCurrentPage }) => {
  return (
    <nav className="bg-black/20 backdrop-blur-sm border-b border-purple-300/20 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-5">
        <div className="flex justify-between items-center h-20">
          <div className="flex items-center">
            <div className="flex-shrink-0 flex items-center">
              <img 
                src={Logo} 
                alt="FormSite Logo" 
                className="h-16 w-auto" 
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-6">
            <button
              onClick={() => setCurrentPage('home')}
              className="relative group text-purple-300 hover:text-white transition-colors duration-300 font-medium"
            >
              Home
              <span className="absolute -bottom-2 left-0 w-0 h-0.5 bg-gradient-to-r from-purple-400 to-white group-hover:w-full transition-all duration-300"></span>
            </button>
            
            <button
              onClick={() => setCurrentPage('request')}
              className="bg-gradient-to-r from-purple-400 to-purple-200 hover:bg-white text-purple-900 hover:text-purple-900 px-4 py-2 rounded-lg font-medium transition-all duration-300 transform hover:scale-105"
            >
              Request
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;