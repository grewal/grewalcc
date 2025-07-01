import React from 'react';

const UserProfileCardShell: React.FC = () => {
  return (
    <div className="bg-gray-800/50 backdrop-blur-sm p-6 md:p-8 rounded-xl shadow-2xl border border-gray-700 text-left w-full max-w-2xl mx-auto">
      <h3 className="text-2xl font-bold text-white mb-6 border-b border-gray-600 pb-4">
        Account Details
      </h3>
      <div className="space-y-4 animate-pulse">
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">Username</span>
          <div className="h-6 bg-gray-700 rounded w-2/4 mt-1 sm:mt-0"></div>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">Email</span>
          <div className="h-6 bg-gray-700 rounded w-3/4 mt-1 sm:mt-0"></div>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">User ID</span>
          <div className="h-4 bg-gray-700 rounded w-full mt-1 sm:mt-0"></div>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between items-start sm:items-center">
          <span className="font-semibold text-gray-400 sm:w-1/4 mb-2 sm:mb-0">Roles</span>
          <div className="flex flex-wrap gap-2 justify-start sm:justify-end">
            <div className="h-5 w-16 bg-gray-700 rounded-full"></div>
            <div className="h-5 w-20 bg-gray-700 rounded-full"></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfileCardShell;
