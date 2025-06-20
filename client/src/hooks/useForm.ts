// ===========================
// src/hooks/useForm.ts - Form state management
// ===========================

import { useState } from 'react';
import type { FormData } from '../types/form';

export const useForm = () => {
  const [formData, setFormData] = useState<FormData>({
    step1: '',
    step2: '',
    step3: '',
    step4: '',
    step5: '',
    step6: '',
    step7: '',
    step8: '',
    name: '',
    email: '',
    country: 'US',
    phone: '',
  });

  const updateFormData = (field: keyof FormData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const resetForm = () => {
    setFormData({
      step1: '',
      step2: '',
      step3: '',
      step4: '',
      step5: '',
      step6: '',
      step7: '',
      step8: '',
      name: '',
      email: '',
      country: 'US',
      phone: '',
    });
  };

  return {
    formData,
    updateFormData,
    resetForm,
  };
};