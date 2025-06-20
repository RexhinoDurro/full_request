// ===========================
// src/components/form/TextQuestion.tsx - Text input questions
// ===========================

import React from 'react';

interface TextQuestionProps {
  question: string;
  value: string;
  onChange: (value: string) => void;
}

const TextQuestion: React.FC<TextQuestionProps> = ({ question, value, onChange }) => {
  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-semibold text-gray-800">{question}</h3>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full p-4 bg-white border-2 border-gray-300 rounded-xl text-gray-800 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none h-32 shadow-sm"
        placeholder="Enter your answer here..."
      />
    </div>
  );
};

export default TextQuestion;