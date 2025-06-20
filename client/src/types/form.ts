// ===========================
// src/types/form.ts - TypeScript interfaces
// ===========================

export interface FormData {
  step1: string;
  step2: string;
  step3: string;
  step4: string;
  step5: string;
  step6: string;
  step7: string;
  step8: string;
  name: string;
  email: string;
  country: string;
  phone: string;
}

export interface Country {
  code: string;
  name: string;
  flag: string;
  prefix: string;
}

export interface Question {
  type: 'text' | 'selection';
  question: string;
  options?: string[];
  field: keyof FormData;
}