'use client';

import React from 'react';

interface User {
  user_id: string;
  username: string;
  email: string;
  roles: string[];
}

interface UserProfileCardProps {
  user: User;
}

const UserProfileCard: React.FC<UserProfileCardProps> = ({ user }) => {
  return (
    <div className="bg-gray-800/50 backdrop-blur-sm p-6 md:p-8 rounded-xl shadow-2xl border border-gray-700 text-left w-full max-w-2xl mx-auto">
      <h3 className="text-2xl font-bold text-white mb-6 border-b border-gray-600 pb-4">
        Account Details
      </h3>
      <div className="space-y-4 text-gray-300">
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">Username</span>
          <span className="font-mono text-blue-400 break-all">{user.username}</span>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">Email</span>
          <span className="font-mono text-blue-400 break-all">{user.email}</span>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between">
          <span className="font-semibold text-gray-400 sm:w-1/4">User ID</span>
          <span className="font-mono text-xs text-gray-500 break-all">{user.user_id}</span>
        </div>
        <div className="flex flex-col sm:flex-row sm:justify-between items-start sm:items-center">
          <span className="font-semibold text-gray-400 sm:w-1/4 mb-2 sm:mb-0">Roles</span>
          <div className="flex flex-wrap gap-2 justify-start sm:justify-end">
            {user.roles.map((role) => (
              <span key={role} className="bg-gray-700 text-gray-200 text-xs font-semibold px-2.5 py-1 rounded-full">
                {role.toUpperCase()}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfileCard;
