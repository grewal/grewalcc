'use client';

export default function LoginForm() {
  return (
    <div className="w-full max-w-xs">
      <form
        action="/api/auth/login"
        method="POST"
        className="bg-gray-700 shadow-md rounded px-8 pt-6 pb-8"
      >
        <div className="mb-4">
          <label
            className="block text-gray-300 text-sm font-bold mb-2"
            htmlFor="email"
          >
            Username or Email
          </label>
          <input
            className="shadow appearance-none border rounded w-full py-2 px-3 bg-gray-600 border-gray-500 text-white leading-tight focus:outline-none focus:shadow-outline"
            id="email"
            type="text"
            name="username_or_email"
            placeholder="your@email.com"
            required
          />
        </div>
        <div className="mb-6">
          <label
            className="block text-gray-300 text-sm font-bold mb-2"
            htmlFor="password"
          >
            Password
          </label>
          <input
            className="shadow appearance-none border rounded w-full py-2 px-3 bg-gray-600 border-gray-500 text-white mb-3 leading-tight focus:outline-none focus:shadow-outline"
            id="password"
            type="password"
            name="password"
            placeholder="******************"
            required
          />
        </div>
        <div className="flex items-center justify-between">
          <button
            className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
            type="submit"
          >
            Sign In
          </button>
        </div>
      </form>
    </div>
  );
}
