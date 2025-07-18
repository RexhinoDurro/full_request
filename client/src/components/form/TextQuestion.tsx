// src/components/form/TextQuestion.tsx - Professional text input questions
import React from 'react';

interface TextQuestionProps {
  question: string;
  value: string;
  onChange: (value: string) => void;
}

const TextQuestion: React.FC<TextQuestionProps> = ({ question, value, onChange }) => {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h3 className="text-2xl font-semibold text-gray-900 leading-tight">{question}</h3>
        <p className="text-gray-600 text-sm">
          Please provide as much detail as possible to help us understand your situation better.
        </p>
      </div>
      
      <div className="relative">
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full p-4 bg-white border-2 border-gray-200 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent resize-none h-40 transition-all duration-200 shadow-sm hover:border-gray-300"
          placeholder="Enter your detailed response here..."
          rows={6}
        />
        <div className="absolute bottom-3 right-3 text-xs text-gray-400">
          {value.length} characters
        </div>
      </div>
      
      {value.length > 0 && value.length < 20 && (
        <div className="flex items-center space-x-2 text-amber-600 text-sm">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          <span>Please provide more details for a better assessment</span>
        </div>
      )}
    </div>
  );
};

export default TextQuestion;