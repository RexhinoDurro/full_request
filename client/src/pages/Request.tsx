// src/pages/Request.tsx - Professional redesigned request page
import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, CheckCircle, AlertCircle, Loader, Shield, Clock, Users } from 'lucide-react';
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
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-purple-50">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="bg-white shadow-2xl rounded-3xl p-12 text-center border border-gray-200">
            {submissionResult.success ? (
              <div className="space-y-8">
                <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto">
                  <CheckCircle className="w-12 h-12 text-green-600" />
                </div>
                <div className="space-y-4">
                  <h2 className="text-3xl font-bold text-gray-900">Application Submitted Successfully!</h2>
                  <p className="text-lg text-gray-600 max-w-2xl mx-auto">{submissionResult.message}</p>
                  {submissionResult.submissionId && (
                    <div className="inline-flex items-center px-4 py-2 bg-green-50 rounded-lg border border-green-200">
                      <span className="text-sm font-medium text-green-800">
                        Reference ID: #{submissionResult.submissionId}
                      </span>
                    </div>
                  )}
                </div>
                <div className="space-y-6 pt-4">
                  <div className="bg-gray-50 rounded-xl p-6">
                    <h3 className="font-semibold text-gray-900 mb-3">What happens next?</h3>
                    <div className="space-y-3 text-left">
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-xs font-bold text-blue-600">1</span>
                        </div>
                        <p className="text-gray-600">Our expert team will review your application within 2-3 business days</p>
                      </div>
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-xs font-bold text-blue-600">2</span>
                        </div>
                        <p className="text-gray-600">You'll receive a detailed email with our assessment and next steps</p>
                      </div>
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-xs font-bold text-blue-600">3</span>
                        </div>
                        <p className="text-gray-600">If approved, we'll schedule a consultation to discuss your case</p>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={handleNewSubmission}
                    className="inline-flex items-center px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors font-medium"
                  >
                    Submit Another Application
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-8">
                <div className="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto">
                  <AlertCircle className="w-12 h-12 text-red-600" />
                </div>
                <div className="space-y-4">
                  <h2 className="text-3xl font-bold text-gray-900">Submission Failed</h2>
                  <p className="text-lg text-gray-600">{submissionResult.message}</p>
                </div>
                <button
                  onClick={() => setSubmissionResult(null)}
                  className="inline-flex items-center px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium"
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
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-purple-50">
      {/* Header Section */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Application Form</h1>
            <p className="text-gray-600 max-w-2xl mx-auto">
              Please provide accurate information to help us understand your case better. 
              All information is kept strictly confidential.
            </p>
          </div>

          {/* Trust Indicators */}
          <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="flex items-center justify-center space-x-3 p-4 bg-gray-50 rounded-lg">
              <Shield className="w-6 h-6 text-green-600" />
              <span className="text-sm font-medium text-gray-700">Secure & Encrypted</span>
            </div>
            <div className="flex items-center justify-center space-x-3 p-4 bg-gray-50 rounded-lg">
              <Clock className="w-6 h-6 text-blue-600" />
              <span className="text-sm font-medium text-gray-700">2-3 Day Review</span>
            </div>
            <div className="flex items-center justify-center space-x-3 p-4 bg-gray-50 rounded-lg">
              <Users className="w-6 h-6 text-purple-600" />
              <span className="text-sm font-medium text-gray-700">Expert Analysis</span>
            </div>
          </div>
        </div>
      </div>

      {/* Form Section */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <StepIndicator currentStep={currentStep} totalSteps={9} />
        
        <div className="bg-white shadow-xl rounded-2xl p-8 md:p-12 mb-8 border border-gray-200">
          {renderCurrentQuestion()}
        </div>
        
        {/* Navigation */}
        <div className="flex justify-between items-center">
          <button
            onClick={handleBack}
            disabled={currentStep === 1}
            className="flex items-center space-x-2 px-6 py-3 bg-white text-gray-600 rounded-lg hover:bg-gray-50 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm border border-gray-300 font-medium"
          >
            <ChevronLeft className="w-5 h-5" />
            <span>Previous</span>
          </button>
          
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-500">
              Step {currentStep} of 9
            </span>
            
            {currentStep === 9 ? (
              <button
                onClick={handleSubmit}
                disabled={!isCurrentStepValid() || isSubmitting}
                className="flex items-center space-x-2 px-8 py-3 bg-gradient-to-r from-purple-600 to-purple-700 text-white rounded-lg hover:from-purple-700 hover:to-purple-800 transition-all duration-200 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 shadow-lg font-medium"
              >
                {isSubmitting ? (
                  <>
                    <Loader className="w-5 h-5 animate-spin" />
                    <span>Submitting...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-5 h-5" />
                    <span>Submit Application</span>
                  </>
                )}
              </button>
            ) : (
              <button
                onClick={handleNext}
                disabled={!isCurrentStepValid()}
                className="flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-purple-700 text-white rounded-lg hover:from-purple-700 hover:to-purple-800 transition-all duration-200 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 shadow-lg font-medium"
              >
                <span>Next</span>
                <ChevronRight className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-8">
          <div className="flex justify-between text-xs text-gray-500 mb-2">
            <span>Progress</span>
            <span>{Math.round((currentStep / 9) * 100)}% Complete</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className="bg-gradient-to-r from-purple-600 to-purple-700 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(currentStep / 9) * 100}%` }}
            ></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RequestPage;