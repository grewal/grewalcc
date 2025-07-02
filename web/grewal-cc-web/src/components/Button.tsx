'use client';

import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary';
}

export function Button({
  children,
  variant = 'primary',
  ...props
}: ButtonProps) {
  const baseStyle =
    'font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition-colors duration-200';
  const variantStyles = {
    primary: 'bg-blue-500 hover:bg-blue-600 text-white',
    secondary: 'bg-gray-600 hover:bg-gray-700 text-gray-200',
  };

  return (
    <button className={`${baseStyle} ${variantStyles[variant]}`} {...props}>
      {children}
    </button>
  );
}
