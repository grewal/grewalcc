import { AuthenticatedUser } from '@/lib/auth/session';

interface UserProfileCardProps {
  user: AuthenticatedUser;
}

export function UserProfileCard({ user }: UserProfileCardProps) {
  return (
    <div className="max-w-md mx-auto bg-gray-800 rounded-xl shadow-md overflow-hidden md:max-w-2xl border border-gray-700">
      <div className="p-8">
        <div className="uppercase tracking-wide text-sm text-indigo-400 font-semibold">
          User Profile
        </div>
        <p className="block mt-1 text-lg leading-tight font-medium text-white">
          {user.username}
        </p>
        <p className="mt-2 text-gray-400">
          <span className="font-semibold">Email:</span> {user.email}
        </p>
        <p className="mt-2 text-gray-400">
          <span className="font-semibold">User ID:</span>{' '}
          <code className="text-xs bg-gray-700 p-1 rounded">{user.id}</code>
        </p>
        <div className="mt-4">
          <span className="font-semibold text-gray-400">Roles:</span>
          <div className="flex flex-wrap gap-2 mt-2">
            {user.roles.map((role) => (
              <span
                key={role}
                className="px-3 py-1 text-sm font-semibold text-green-200 bg-green-800/50 rounded-full"
              >
                {role}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
