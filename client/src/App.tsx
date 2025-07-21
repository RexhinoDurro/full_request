// src/App.tsx - Main app with routing (FIXED VERSION)
import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import HomePage from './pages/Home';
import RequestPage from './pages/Request';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState('home');

  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: '#000080' }}>
      <Navbar currentPage={currentPage} setCurrentPage={setCurrentPage} />
      
      {currentPage === 'home' ? <HomePage /> : <RequestPage />}
      
      <Footer />
    </div>
  );
};

export default App;