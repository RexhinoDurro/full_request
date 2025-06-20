// ===========================
// src/pages/Request.tsx - Form page with Django backend integration
// ===========================

import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, CheckCircle, AlertCircle, Loader } from 'lucide-react';
import StepIndicator from '../components/StepIndicator';
import TextQuestion from '../components/form/TextQuestion';
import SelectionQuestion from '../components/form/SelectionQuestion';
import ContactInfo from '../components/form/ContactInfo';
import { useForm } from '../hooks/useForm';
import { submitFormData } from '../utils/api';
import type { Question } from '../types/form';

const RequestPage: React.FC = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionResult, setSubmissionResult] = useState<{
    success: boolean;
    message: string;
    submissionId?: number;
  } | null>(null);
  
  const { formData, updateFormData, resetForm } = useForm();

  const questions: Question[] = [
    {
      type: 'text',
      question: 'Could you please share the name of the company involved in your case?',
      field: 'step1',
    },
    {
      type: 'selection',
      question: 'What type of services or business was the company involved in?',
      options: ['investment fund', 'broker', 'cryptocurrency wallet/exchange', 'other'],
      field: 'step2',
    },
    {
      type: 'selection',
      question: 'When did the financial issue occur?',
      options: ['less than a month', 'up to three months', 'less than a year', 'more than a year'],
      field: 'step3',
    },
    {
      type: 'selection',
      question: 'Has the company acknowledged the presence of your funds?',
      options: ['Yes, full-time', 'Yes, part-time', 'No', 'Partially'],
      field: 'step4',
    },
    {
      type: 'selection',
      question: 'What is your primary goal for joining?',
      options: ['Networking', 'Career Development', 'Learning', 'Business Growth'],
      field: 'step5',
    },
    {
      type: 'selection',
      question: 'How did you hear about us?',
      options: ['Social Media', 'Friend Referral', 'Online Search', 'Advertisement'],
      field: 'step6',
    },
    {
      type: 'selection',
      question: 'What is your preferred communication method?',
      options: ['Email', 'Phone', 'Text Message', 'Video Call'],
      field: 'step7',
    },
    {
      type: 'text',
      question:'Could you summarize the key details of your case that you think are important and helpful?',
      field: 'step8',
    },
  ];

  const isCurrentStepValid = () => {
    if (currentStep <= 8) {
      const field = questions[currentStep - 1].field;
      return formData[field].trim() !== '';
    } else {
      return formData.name.trim() !== '' && 
             formData.email.trim() !== '' && 
             formData.phone.trim() !== '';
    }
  };

  const handleNext = () => {
    if (isCurrentStepValid() && currentStep < 9) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSubmit = async () => {
    if (!isCurrentStepValid() || isSubmitting) return;

    setIsSubmitting(true);
    
    try {
      const result = await submitFormData(formData);
      setSubmissionResult(result);
      
      if (result.success) {
        // Reset form on successful submission
        setTimeout(() => {
          resetForm();
          setCurrentStep(1);
          setSubmissionResult(null);
        }, 5000);
      }
    } catch (error) {
      setSubmissionResult({
        success: false,
        message: 'Network error. Please check your connection and try again.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleNewSubmission = () => {
    setSubmissionResult(null);
    resetForm();
    setCurrentStep(1);
  };

  // Show submission result
  if (submissionResult) {
    return (
      <div className="flex-1 py-12 bg-gradient-to-br from-blue-50 to-purple-50 min-h-screen">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white shadow-2xl rounded-2xl p-12 text-center">
            {submissionResult.success ? (
              <div className="space-y-6">
                <CheckCircle className="w-16 h-16 text-green-500 mx-auto" />
                <h2 className="text-3xl font-bold text-gray-800">Submission Successful!</h2>
                <p className="text-lg text-gray-600">{submissionResult.message}</p>
                {submissionResult.submissionId && (
                  <p className="text-sm text-gray-500">
                    Reference ID: #{submissionResult.submissionId}
                  </p>
                )}
                <div className="space-y-4">
                  <p className="text-gray-600">
                    Thank you for your submission. Our team will review your information and get back to you soon.
                  </p>
                  <button
                    onClick={handleNewSubmission}
                    className="px-8 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
                  >
                    Submit Another Form
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-6">
                <AlertCircle className="w-16 h-16 text-red-500 mx-auto" />
                <h2 className="text-3xl font-bold text-gray-800">Submission Failed</h2>
                <p className="text-lg text-gray-600">{submissionResult.message}</p>
                <button
                  onClick={() => setSubmissionResult(null)}
                  className="px-8 py-3 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
                >
                  Try Again
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  const renderCurrentQuestion = () => {
    if (currentStep <= 8) {
      const question = questions[currentStep - 1];
      if (question.type === 'text') {
        return (
          <TextQuestion
            question={question.question}
            value={formData[question.field]}
            onChange={(value) => updateFormData(question.field, value)}
          />
        );
      } else {
        return (
          <SelectionQuestion
            question={question.question}
            options={question.options || []}
            value={formData[question.field]}
            onChange={(value) => updateFormData(question.field, value)}
          />
        );
      }
    } else {
      return <ContactInfo formData={formData} onChange={updateFormData} />;
    }
  };

  return (
    <div className="flex-1 py-12 bg-gradient-to-br from-blue-50 to-purple-50 min-h-screen">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <StepIndicator currentStep={currentStep} totalSteps={9} />
        
        <div className="bg-white shadow-2xl rounded-2xl p-12 mb-8 border border-gray-200">
          {renderCurrentQuestion()}
        </div>
        
        <div className="flex justify-between items-center">
          <button
            onClick={handleBack}
            disabled={currentStep === 1}
            className="flex items-center space-x-2 px-8 py-4 bg-gray-100 text-gray-600 rounded-xl hover:bg-gray-200 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
          >
            <ChevronLeft className="w-5 h-5" />
            <span className="font-medium">Back</span>
          </button>
          
          {currentStep === 9 ? (
            <button
              onClick={handleSubmit}
              disabled={!isCurrentStepValid() || isSubmitting}
              className="flex items-center space-x-2 px-10 py-4 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-xl hover:from-green-600 hover:to-green-700 transition-all duration-300 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 shadow-lg font-medium"
            >
              {isSubmitting ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Submitting...</span>
                </>
              ) : (
                <span>Submit Application</span>
              )}
            </button>
          ) : (
            <button
              onClick={handleNext}
              disabled={!isCurrentStepValid()}
              className="flex items-center space-x-2 px-8 py-4 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 shadow-lg"
            >
              <span className="font-medium">Next</span>
              <ChevronRight className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default RequestPage;