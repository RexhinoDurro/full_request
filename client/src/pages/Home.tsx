// src/pages/Home.tsx - Professional redesigned homepage
import React, { useState } from 'react';
import { ChevronDown, ChevronUp, FileText, Shield, BarChart3, Users, ArrowRight, CheckCircle } from 'lucide-react';
import CryptoSlider from '../components/CryptoSlider';

interface HomePageProps {
  setCurrentPage: (page: string) => void;
}

const HomePage: React.FC<HomePageProps> = ({ setCurrentPage }) => {
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const faqs = [
    {
      question: "What is FormSite?",
      answer: "FormSite is a comprehensive platform for creating and managing digital forms and applications. We provide a seamless experience for both form creators and applicants with enterprise-grade security."
    },
    {
      question: "How do I apply for membership?",
      answer: "Simply click the 'Submit a Form' button and fill out our comprehensive 9-step application form. The process takes just a few minutes and includes contact information and case details."
    },
    {
      question: "Is my information secure?",
      answer: "Yes, we take security seriously. All data is encrypted using industry-standard protocols and stored securely. We never share your personal information with third parties without your explicit consent."
    },
    {
      question: "How long does the approval process take?",
      answer: "Our experienced team reviews applications within 2-3 business days. You'll receive an email notification with detailed feedback once your application has been processed."
    },
    {
      question: "Can I edit my application after submission?",
      answer: "Unfortunately, applications cannot be edited once submitted to maintain data integrity. However, you can contact our support team if you need to make important corrections or submit additional information."
    },
    {
      question: "What types of cases do you handle?",
      answer: "We handle a wide variety of financial cases including investment funds, brokers, cryptocurrency exchanges, and other financial service disputes. Our team has expertise across multiple sectors."
    }
  ];

  const features = [
    {
      icon: Shield,
      title: "Advanced Security",
      description: "Enterprise-grade encryption and security protocols protect your sensitive information at every step."
    },
    {
      icon: BarChart3,
      title: "Real-time Analytics",
      description: "Comprehensive dashboard with detailed insights and analytics on form performance and submission trends."
    },
    {
      icon: Users,
      title: "Expert Team",
      description: "Our experienced professionals review every submission with meticulous attention to detail and industry expertise."
    },
    {
      icon: FileText,
      title: "Smart Forms",
      description: "Intelligent form system that adapts to user responses and ensures optimal data collection efficiency."
    }
  ];

  return (
    <div className="flex-1">
      {/* Hero Section */}
      <div className="min-h-screen flex items-center">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 w-full">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            {/* Left Section - Desktop order / Second on mobile */}
            <div className="text-left space-y-8 order-2 lg:order-1">
              <h1 className="text-6xl lg:text-7xl font-extrabold text-white leading-tight">
                Welcome to
                <span className="block bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                  FormSite
                </span>
              </h1>
              <p className="text-xl text-purple-200 leading-relaxed max-w-lg">
                Your trusted gateway to seamless form submissions and professional digital experiences. Submit your case with confidence.
              </p>
              <div className="flex items-center space-x-4 text-purple-300">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span>Secure & Confidential</span>
              </div>
            </div>
            
            {/* Right Section - Submit Form - First on mobile */}
            <div className="flex justify-center lg:justify-end order-1 lg:order-2">
              <div className="relative group">
                <div className="w-96 h-96 bg-gradient-to-br from-purple-400/10 to-pink-400/10 rounded-3xl backdrop-blur-sm border border-purple-300/20 flex flex-col items-center justify-center p-8 hover:from-purple-400/20 hover:to-pink-400/20 transition-all duration-500">
                  <div className="text-center space-y-6">
                    <div className="w-20 h-20 bg-gradient-to-br from-purple-500/30 to-pink-500/30 rounded-full flex items-center justify-center mx-auto group-hover:scale-110 transition-transform duration-300">
                      <FileText className="w-10 h-10 text-purple-200" />
                    </div>
                    
                    <div className="space-y-4">
                      <h3 className="text-2xl font-bold text-white">Submit a Form</h3>
                      <p className="text-purple-200 text-sm leading-relaxed">
                        Start your application process with our comprehensive form system
                      </p>
                    </div>
                    
                    <button
                      onClick={() => setCurrentPage('request')}
                      className="group/btn bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-8 py-4 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 flex items-center space-x-2 shadow-lg hover:shadow-purple-500/25"
                    >
                      <span>Make a Request</span>
                      <ArrowRight className="w-5 h-5 group-hover/btn:translate-x-1 transition-transform duration-300" />
                    </button>
                  </div>
                </div>
                
                {/* Floating elements */}
                <div className="absolute -top-4 -left-4 w-16 h-16 bg-purple-400/20 rounded-full blur-xl animate-pulse"></div>
                <div className="absolute -bottom-4 -right-4 w-20 h-20 bg-pink-400/20 rounded-full blur-xl animate-pulse delay-1000"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Crypto Slider */}
      <CryptoSlider />

      {/* About Us Section */}
      <div className="py-24 bg-gradient-to-b from-transparent to-black/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20">
            <h2 className="text-5xl font-bold text-white mb-6">
              About <span className="bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">FormSite</span>
            </h2>
            <p className="text-xl text-purple-200 max-w-4xl mx-auto leading-relaxed">
              We're revolutionizing how organizations and individuals handle complex form submissions with cutting-edge technology, 
              unparalleled security, and expert professional guidance.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <div key={index} className="group">
                <div className="text-center p-8 bg-gradient-to-b from-white/5 to-white/10 rounded-2xl border border-purple-300/20 hover:border-purple-300/40 transition-all duration-500 hover:transform hover:-translate-y-2 backdrop-blur-sm">
                  <div className="w-16 h-16 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl flex items-center justify-center mx-auto mb-6 group-hover:from-purple-500/30 group-hover:to-pink-500/30 transition-all duration-300">
                    <feature.icon className="w-8 h-8 text-purple-300 group-hover:text-purple-200 transition-colors duration-300" />
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-4 group-hover:text-purple-200 transition-colors duration-300">
                    {feature.title}
                  </h3>
                  <p className="text-purple-300 leading-relaxed text-sm">
                    {feature.description}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Stats Section */}
          <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center p-8 bg-gradient-to-br from-purple-500/10 to-transparent rounded-2xl border border-purple-300/20">
              <div className="text-4xl font-bold text-white mb-2">10,000+</div>
              <div className="text-purple-300">Forms Processed</div>
            </div>
            <div className="text-center p-8 bg-gradient-to-br from-pink-500/10 to-transparent rounded-2xl border border-purple-300/20">
              <div className="text-4xl font-bold text-white mb-2">99.9%</div>
              <div className="text-purple-300">Uptime Guarantee</div>
            </div>
            <div className="text-center p-8 bg-gradient-to-br from-blue-500/10 to-transparent rounded-2xl border border-purple-300/20">
              <div className="text-4xl font-bold text-white mb-2">24/7</div>
              <div className="text-purple-300">Expert Support</div>
            </div>
          </div>
        </div>
      </div>

      {/* FAQ Section */}
      <div className="py-24 bg-gradient-to-b from-black/20 to-black/40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-start">
            {/* Left Section - FAQ Header */}
            <div className="lg:sticky lg:top-8">
              <h2 className="text-5xl font-bold text-white mb-8">
                <span className="bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">FAQ</span>
              </h2>
              <div className="space-y-6">
                <p className="text-2xl text-white font-semibold">
                  Still have some questions?
                </p>
                <p className="text-lg text-purple-200 leading-relaxed">
                  Find answers to the most commonly asked questions about our platform, 
                  security measures, and application process.
                </p>
                <div className="pt-4">
                  <button className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-6 py-3 rounded-lg font-medium transition-all duration-300 transform hover:scale-105">
                    Contact Support
                  </button>
                </div>
              </div>
            </div>
            
            {/* Right Section - FAQ Items */}
            <div className="space-y-4">
              {faqs.map((faq, index) => (
                <div key={index} className="bg-white/5 backdrop-blur-sm border border-purple-300/20 rounded-xl overflow-hidden hover:border-purple-300/40 transition-all duration-300">
                  <button
                    onClick={() => setOpenFaq(openFaq === index ? null : index)}
                    className="w-full px-6 py-5 text-left flex justify-between items-center hover:bg-white/5 transition-colors duration-200"
                  >
                    <span className="text-lg font-medium text-white pr-4">{faq.question}</span>
                    <div className="flex-shrink-0">
                      {openFaq === index ? (
                        <ChevronUp className="w-5 h-5 text-purple-300" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-purple-300" />
                      )}
                    </div>
                  </button>
                  {openFaq === index && (
                    <div className="px-6 pb-5 border-t border-purple-300/10">
                      <p className="text-purple-200 leading-relaxed pt-4">{faq.answer}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;