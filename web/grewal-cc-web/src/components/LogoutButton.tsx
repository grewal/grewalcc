'use client';

import React, { useState, FormEvent } from 'react';

const LogoutButton = () => {
  const [isLoading, setIsLoading] = useState(false);

  const handleLogout = async (event: FormEvent) => {
    // 1. Prevent the browser's default navigation behavior
    event.preventDefault();
    setIsLoading(true);

    try {
      // 2. Manually make the API call in the background
      const res = await fetch('/api/auth/logout', { method: 'POST' });

      // 3. If the logout was successful, reload the page
      if (res.ok) {
        window.location.reload();
      } else {
        console.error('Logout failed');
        setIsLoading(false);
      }
    } catch (error) {
      console.error('Error during logout:', error);
      setIsLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center p-6 md:p-12 w-full">
      <div className="mx-auto w-full max-w-[550px] bg-gray-800/50 backdrop-blur-sm p-8 rounded-xl shadow-2xl border border-gray-700">
        <h2 className="text-2xl font-bold text-center text-white mb-6">
          You are logged in.
        </h2>
        
        <form onSubmit={handleLogout}>
          <button
            type="submit"
            disabled={isLoading}
            className="hover:shadow-red-500/50 w-full rounded-md bg-red-600 hover:bg-red-700 py-3 px-8 text-center text-base font-semibold text-white outline-none shadow-md transition-all duration-300 ease-in-out disabled:bg-gray-500 disabled:cursor-not-allowed"
          >
            {isLoading ? 'Logging out...' : 'Logout'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default LogoutButton;
