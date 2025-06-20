// src/pages/Home.tsx - Fixed Landing page component
import React, { useState } from 'react';
import { FileText, ChevronDown, ChevronUp } from 'lucide-react';

const HomePage: React.FC = () => {
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const faqs = [
    {
      question: "What is FormSite?",
      answer: "FormSite is a comprehensive platform for creating and managing digital forms and applications. We provide a seamless experience for both form creators and applicants."
    },
    {
      question: "How do I apply for membership?",
      answer: "Simply click the 'Request' button in the navigation bar and fill out our comprehensive 9-step application form. The process takes just a few minutes."
    },
    {
      question: "Is my information secure?",
      answer: "Yes, we take security seriously. All data is encrypted and stored securely. We never share your personal information with third parties without your consent."
    },
    {
      question: "How long does the approval process take?",
      answer: "Our team reviews applications within 2-3 business days. You'll receive an email notification once your application has been processed."
    },
    {
      question: "Can I edit my application after submission?",
      answer: "Unfortunately, applications cannot be edited once submitted. However, you can contact our support team if you need to make important corrections."
    }
  ];

  return (
    <div className="flex-1">
      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div className="text-left">
            <h1 className="text-6xl lg:text-7xl font-extrabold text-white leading-tight mb-6">
              Welcome to FormSite
            </h1>
            <p className="text-xl text-purple-200 mb-8 leading-relaxed">
              Your gateway to seamless form submissions and digital experiences
            </p>
            <p className="text-lg text-purple-300 font-normal">
              Apply to become a member
            </p>
          </div>
          
          <div className="flex justify-center lg:justify-end">
            <div className="relative">
              <div className="w-96 h-96 bg-gradient-to-br from-purple-400/20 to-pink-400/20 rounded-3xl backdrop-blur-sm border border-purple-300/30 flex items-center justify-center">
                <div className="w-80 h-80 bg-gradient-to-br from-purple-500/30 to-pink-500/30 rounded-2xl flex items-center justify-center">
                  <FileText className="w-32 h-32 text-purple-200" />
                </div>
              </div>
              <div className="absolute -top-4 -left-4 w-16 h-16 bg-purple-400/30 rounded-full blur-xl"></div>
              <div className="absolute -bottom-4 -right-4 w-20 h-20 bg-pink-400/30 rounded-full blur-xl"></div>
            </div>
          </div>
        </div>
      </div>

      {/* About Us Section */}
      <div className="bg-white/5 backdrop-blur-sm border-y border-purple-300/20 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">About FormSite</h2>
            <p className="text-xl text-purple-200 max-w-3xl mx-auto">
              We're dedicated to revolutionizing how organizations collect and process information through intelligent form solutions.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center p-8 bg-white/5 rounded-xl border border-purple-300/20">
              <div className="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <FileText className="w-8 h-8 text-purple-300" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-4">Smart Forms</h3>
              <p className="text-purple-200">
                Create intelligent forms that adapt to user responses and provide a seamless experience.
              </p>
            </div>
            
            <div className="text-center p-8 bg-white/5 rounded-xl border border-purple-300/20">
              <div className="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <FileText className="w-8 h-8 text-purple-300" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-4">Secure Processing</h3>
              <p className="text-purple-200">
                Your data is protected with enterprise-grade security and encryption standards.
              </p>
            </div>
            
            <div className="text-center p-8 bg-white/5 rounded-xl border border-purple-300/20">
              <div className="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <FileText className="w-8 h-8 text-purple-300" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-4">Analytics</h3>
              <p className="text-purple-200">
                Get detailed insights and analytics on form performance and user behavior.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* FAQ Section */}
      <div className="py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">Frequently Asked Questions</h2>
            <p className="text-xl text-purple-200">
              Find answers to common questions about our platform and services.
            </p>
          </div>
          
          <div className="space-y-4">
            {faqs.map((faq, index) => (
              <div key={index} className="bg-white/5 backdrop-blur-sm border border-purple-300/20 rounded-xl overflow-hidden">
                <button
                  onClick={() => setOpenFaq(openFaq === index ? null : index)}
                  className="w-full px-6 py-4 text-left flex justify-between items-center hover:bg-white/5 transition-colors duration-200"
                >
                  <span className="text-lg font-medium text-white">{faq.question}</span>
                  {openFaq === index ? (
                    <ChevronUp className="w-5 h-5 text-purple-300" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-purple-300" />
                  )}
                </button>
                {openFaq === index && (
                  <div className="px-6 pb-4">
                    <p className="text-purple-200 leading-relaxed">{faq.answer}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;