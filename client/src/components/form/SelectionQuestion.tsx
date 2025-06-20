// ===========================
// src/components/form/SelectionQuestion.tsx - Multiple choice questions
// ===========================

import React from 'react';

interface SelectionQuestionProps {
  question: string;
  options: string[];
  value: string;
  onChange: (value: string) => void;
}

const SelectionQuestion: React.FC<SelectionQuestionProps> = ({ question, options, value, onChange }) => {
  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-semibold text-gray-800">{question}</h3>
      <div className="space-y-4">
        {options.map((option, index) => (
          <label key={index} className="flex items-center space-x-4 cursor-pointer group p-4 rounded-lg hover:bg-blue-50 transition-colors duration-200">
            <input
              type="radio"
              name="selection"
              value={option}
              checked={value === option}
              onChange={(e) => onChange(e.target.value)}
              className="w-5 h-5 text-blue-500 focus:ring-blue-500 focus:ring-2"
            />
            <span className="text-lg text-gray-700 group-hover:text-blue-600 transition-colors duration-200">
              {option}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
};

export default SelectionQuestion;