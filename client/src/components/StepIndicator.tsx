// src/components/StepIndicator.tsx - Professional step indicator
import React from 'react';
import { Check } from 'lucide-react';

interface StepIndicatorProps {
  currentStep: number;
  totalSteps: number;
}

const StepIndicator: React.FC<StepIndicatorProps> = ({ currentStep, totalSteps }) => {
  const stepLabels = [
    'Company Details',
    'Business Type',
    'Timeline',
    'Fund Status',
    'Goals',
    'Discovery',
    'Communication',
    'Case Summary',
    'Contact Info'
  ];

  return (
    <div className="mb-12">
      {/* Mobile: Simple progress indicator */}
      <div className="block md:hidden">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-gray-700">
            Step {currentStep} of {totalSteps}
          </span>
          <span className="text-sm text-gray-500">
            {stepLabels[currentStep - 1]}
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div 
            className="bg-gradient-to-r from-purple-600 to-purple-700 h-2 rounded-full transition-all duration-500"
            style={{ width: `${(currentStep / totalSteps) * 100}%` }}
          ></div>
        </div>
      </div>

      {/* Desktop: Full step indicator */}
      <div className="hidden md:block">
        <div className="flex items-center justify-between">
          {Array.from({ length: totalSteps }, (_, index) => {
            const stepNumber = index + 1;
            const isCompleted = stepNumber < currentStep;
            const isCurrent = stepNumber === currentStep;
            const isUpcoming = stepNumber > currentStep;

            return (
              <div key={stepNumber} className="flex items-center">
                <div className="flex flex-col items-center">
                  {/* Step Circle */}
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-semibold transition-all duration-300 ${
                      isCompleted
                        ? 'bg-green-500 text-white shadow-lg'
                        : isCurrent
                        ? 'bg-purple-600 text-white shadow-lg ring-4 ring-purple-200'
                        : 'bg-gray-200 text-gray-600 border-2 border-gray-300'
                    }`}
                  >
                    {isCompleted ? (
                      <Check className="w-5 h-5" />
                    ) : (
                      stepNumber
                    )}
                  </div>
                  
                  {/* Step Label */}
                  <div className="mt-2 text-center">
                    <div className={`text-xs font-medium max-w-20 ${
                      isCurrent ? 'text-purple-600' : 
                      isCompleted ? 'text-green-600' : 
                      'text-gray-500'
                    }`}>
                      {stepLabels[index]}
                    </div>
                  </div>
                </div>
                
                {/* Connector Line */}
                {index < totalSteps - 1 && (
                  <div className={`flex-1 h-0.5 mx-4 transition-all duration-300 ${
                    stepNumber < currentStep ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default StepIndicator;