'use client';

import React from 'react';

const LogoutButton = () => {
  return (
    <div className="flex items-center justify-center p-6 md:p-12 w-full">
      <div className="mx-auto w-full max-w-[550px] bg-gray-800/50 backdrop-blur-sm p-8 rounded-xl shadow-2xl border border-gray-700">
        <h2 className="text-2xl font-bold text-center text-white mb-6">
          You are logged in.
        </h2>
        <button
          className="hover:shadow-red-500/50 w-full rounded-md bg-red-600 hover:bg-red-700 py-3 px-8 text-center text-base font-semibold text-white outline-none shadow-md transition-all duration-300 ease-in-out"
        >
          Logout
        </button>
      </div>
    </div>
  );
};

export default LogoutButton;
