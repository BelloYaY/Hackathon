import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function shortId(value: string, left = 8, right = 6) {
  if (!value) return '-';
  if (value.length <= left + right + 1) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

export function formatTime(value?: string | null) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function randomId(prefix: string) {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

export function riskToNumber(risk: string) {
  switch (risk) {
    case 'low':
      return 1;
    case 'guarded':
      return 2;
    case 'elevated':
      return 3;
    case 'high':
      return 4;
    case 'critical':
      return 5;
    default:
      return 0;
  }
}
