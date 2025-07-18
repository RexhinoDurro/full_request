// admin/src/components/Navbar.tsx - Updated with security navigation
import React from 'react';
import { LogOut, User, Shield, BarChart3, FileText, Home } from 'lucide-react';
import { adminApiClient } from '../utils/api';

type CurrentPage = 'dashboard' | 'security' | 'submissions' | 'analytics';

interface NavbarProps {
  username?: string;
  onLogout: () => void;
  currentPage: CurrentPage;
  onPageChange: (page: CurrentPage) => void;
}

const Navbar: React.FC<NavbarProps> = ({ username, onLogout, currentPage, onPageChange }) => {
  const handleLogout = async () => {
    try {
      await adminApiClient.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      onLogout();
    }
  };

  const navItems = [
    {
      id: 'dashboard' as CurrentPage,
      label: 'Dashboard',
      icon: Home,
      description: 'Overview and main dashboard'
    },
    {
      id: 'security' as CurrentPage,
      label: 'Security',
      icon: Shield,
      description: 'Security monitoring and threat analysis'
    }
  ];

  return (
    <nav className="bg-white shadow-lg border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo and Navigation */}
          <div className="flex items-center space-x-8">
            <div className="flex-shrink-0">
              <h1 className="text-xl font-bold text-gray-800 flex items-center">
                <Shield className="w-6 h-6 text-blue-600 mr-2" />
                FormSite Admin
              </h1>
            </div>
            
            {/* Navigation Items */}
            <div className="hidden md:flex space-x-4">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentPage === item.id;
                
                return (
                  <button
                    key={item.id}
                    onClick={() => onPageChange(item.id)}
                    className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors duration-200 ${
                      isActive
                        ? 'bg-blue-100 text-blue-700 border border-blue-200'
                        : 'text-gray-600 hover:text-gray-800 hover:bg-gray-100'
                    }`}
                    title={item.description}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="font-medium">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
          
          {/* User Menu */}
          <div className="flex items-center space-x-4">
            {/* User Info */}
            <div className="flex items-center space-x-2 text-gray-600">
              <User className="w-5 h-5" />
              <span className="text-sm font-medium">{username || 'Admin'}</span>
            </div>
            
            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="flex items-center space-x-2 px-3 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
              <span className="text-sm font-medium hidden sm:block">Logout</span>
            </button>
          </div>
        </div>
        
        {/* Mobile Navigation */}
        <div className="md:hidden pb-4">
          <div className="flex space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;
              
              return (
                <button
                  key={item.id}
                  onClick={() => onPageChange(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors duration-200 text-sm ${
                    isActive
                      ? 'bg-blue-100 text-blue-700 border border-blue-200'
                      : 'text-gray-600 hover:text-gray-800 hover:bg-gray-100'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;