// src/components/form/SelectionQuestion.tsx - Professional multiple choice questions
import React from 'react';
import { Check } from 'lucide-react';

interface SelectionQuestionProps {
  question: string;
  options: string[];
  value: string;
  onChange: (value: string) => void;
}

const SelectionQuestion: React.FC<SelectionQuestionProps> = ({ question, options, value, onChange }) => {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h3 className="text-2xl font-semibold text-gray-900 leading-tight">{question}</h3>
        <p className="text-gray-600 text-sm">
          Please select the option that best describes your situation.
        </p>
      </div>
      
      <div className="space-y-3">
        {options.map((option, index) => {
          const isSelected = value === option;
          
          return (
            <label 
              key={index} 
              className={`flex items-center space-x-4 cursor-pointer group p-4 rounded-xl border-2 transition-all duration-200 ${
                isSelected 
                  ? 'border-purple-500 bg-purple-50 shadow-md' 
                  : 'border-gray-200 bg-white hover:border-purple-200 hover:bg-purple-25 shadow-sm hover:shadow-md'
              }`}
            >
              <div className="relative">
                <input
                  type="radio"
                  name="selection"
                  value={option}
                  checked={isSelected}
                  onChange={(e) => onChange(e.target.value)}
                  className="sr-only"
                />
                <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all duration-200 ${
                  isSelected 
                    ? 'border-purple-500 bg-purple-500' 
                    : 'border-gray-300 bg-white group-hover:border-purple-300'
                }`}>
                  {isSelected && (
                    <Check className="w-3 h-3 text-white" strokeWidth={3} />
                  )}
                </div>
              </div>
              
              <span className={`text-lg font-medium transition-colors duration-200 ${
                isSelected 
                  ? 'text-purple-700' 
                  : 'text-gray-700 group-hover:text-purple-600'
              }`}>
                {option}
              </span>
            </label>
          );
        })}
      </div>
      
      {value && (
        <div className="flex items-center space-x-2 text-green-600 text-sm mt-4">
          <Check className="w-4 h-4" />
          <span>Selection confirmed</span>
        </div>
      )}
    </div>
  );
};

export default SelectionQuestion;