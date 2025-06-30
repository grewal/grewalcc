// File: web/grewal-cc-web/src/components/LoginForm.tsx

'use client';

import React, { useState } from 'react';

interface LoginFormProps {}

const LoginForm: React.FC<LoginFormProps> = () => {
  // State hooks to manage the input field values
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null); // State for error messages
  const [isLoading, setIsLoading] = useState(false); // State for loading indicator

  // The form submission handler
  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const responseData = await res.json();

      if (!res.ok) {
        throw new Error(responseData.message || 'Failed to login');
      }

      // On success, reload the page.
      window.location.reload();

    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center p-6 md:p-12 w-full">
      <div className="mx-auto w-full max-w-[550px] bg-gray-800/50 backdrop-blur-sm p-8 rounded-xl shadow-2xl border border-gray-700">
        <h2 className="text-2xl font-bold text-center text-white mb-6">Grewal.cc Login</h2>
        
        <form onSubmit={handleSubmit}> 
          <div className="mb-5">
            <label htmlFor="email" className="mb-3 block text-base font-medium text-gray-300">
              Email Address
            </label>
            <input
              type="email"
              name="email"
              id="email"
              placeholder="example@grewal.cc"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full rounded-md border border-gray-600 bg-gray-700 py-3 px-6 text-base font-medium text-gray-200 placeholder-gray-500 outline-none focus:border-blue-500 focus:shadow-md transition-all duration-300"
            />
          </div>
          <div className="mb-5">
            <label htmlFor="password" className="mb-3 block text-base font-medium text-gray-300">
              Password
            </label>
            <input
              type="password"
              name="password"
              id="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required // Add basic browser validation
              className="w-full rounded-md border border-gray-600 bg-gray-700 py-3 px-6 text-base font-medium text-gray-200 placeholder-gray-500 outline-none focus:border-blue-500 focus:shadow-md transition-all duration-300"
            />
          </div>
          
          {/* Display error messages */}
          {error && (
            <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-md text-red-300 text-center">
              {error}
            </div>
          )}

          <div>
            <button 
              type="submit"
              disabled={isLoading}
              className="hover:shadow-blue-500/50 w-full rounded-md bg-blue-600 hover:bg-blue-700 py-3 px-8 text-center text-base font-semibold text-white outline-none shadow-md transition-all duration-300 ease-in-out disabled:bg-gray-500 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Logging in...' : 'Login'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
