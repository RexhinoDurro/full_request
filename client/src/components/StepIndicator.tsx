// ===========================
// src/components/StepIndicator.tsx - Progress indicator
// ===========================

import React from 'react';

interface StepIndicatorProps {
  currentStep: number;
  totalSteps: number;
}

const StepIndicator: React.FC<StepIndicatorProps> = ({ currentStep, totalSteps }) => {
  return (
    <div className="flex justify-center items-center space-x-2 mb-8">
      {Array.from({ length: totalSteps }, (_, index) => (
        <div key={index + 1} className="flex items-center">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium transition-all duration-300 ${
              index + 1 === currentStep
                ? 'bg-blue-500 text-white shadow-lg'
                : index + 1 < currentStep
                ? 'bg-green-500 text-white'
                : 'bg-gray-200 text-gray-600 border border-gray-300'
            }`}
          >
            {index + 1}
          </div>
          {index < totalSteps - 1 && (
            <div className={`w-8 h-0.5 ${index + 1 < currentStep ? 'bg-green-500' : 'bg-gray-300'}`} />
          )}
        </div>
      ))}
    </div>
  );
};

export default StepIndicator;
