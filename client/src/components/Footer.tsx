// ===========================
// src/components/Footer.tsx - Footer with social links
// ===========================

import React from 'react';
import { Facebook, Twitter, Instagram, Linkedin } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-black/30 border-t border-purple-300/20 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-center items-center space-x-6">
          <a href="#" className="text-purple-300 hover:text-white transition-colors duration-300 p-2 rounded-full hover:bg-purple-500/20">
            <Facebook className="h-6 w-6" />
          </a>
          <a href="#" className="text-purple-300 hover:text-white transition-colors duration-300 p-2 rounded-full hover:bg-purple-500/20">
            <Twitter className="h-6 w-6" />
          </a>
          <a href="#" className="text-purple-300 hover:text-white transition-colors duration-300 p-2 rounded-full hover:bg-purple-500/20">
            <Instagram className="h-6 w-6" />
          </a>
          <a href="#" className="text-purple-300 hover:text-white transition-colors duration-300 p-2 rounded-full hover:bg-purple-500/20">
            <Linkedin className="h-6 w-6" />
          </a>
        </div>
        <div className="text-center text-purple-300 text-sm mt-4">
          © 2025 FormSite. All rights reserved.
        </div>
      </div>
    </footer>
  );
};

export default Footer;