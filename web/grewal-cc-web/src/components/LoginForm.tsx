// File: web/grewal-cc-web/src/components/LoginForm.tsx

'use client';

import React, { useState } from 'react';

// Define the component's properties interface (empty for now, but good practice)
interface LoginFormProps {}

const LoginForm: React.FC<LoginFormProps> = () => {
  // State hooks to manage the input field values
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  return (
    <div className="flex items-center justify-center p-6 md:p-12 w-full">
      <div className="mx-auto w-full max-w-[550px] bg-gray-800/50 backdrop-blur-sm p-8 rounded-xl shadow-2xl border border-gray-700">
        <h2 className="text-2xl font-bold text-center text-white mb-6">Grewal.cc Login</h2>
        <form>
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
              className="w-full rounded-md border border-gray-600 bg-gray-700 py-3 px-6 text-base font-medium text-gray-200 placeholder-gray-500 outline-none focus:border-purple-500 focus:shadow-md transition-all duration-300"
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
              className="w-full rounded-md border border-gray-600 bg-gray-700 py-3 px-6 text-base font-medium text-gray-200 placeholder-gray-500 outline-none focus:border-purple-500 focus:shadow-md transition-all duration-300"
            />
          </div>
          <div>
            <button className="hover:shadow-blue-500/50 w-full rounded-md bg-blue-600 hover:bg-blue-700 py-3 px-8 text-center text-base font-semibold text-white outline-none shadow-md transition-all duration-300 ease-in-out">
              Login
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
