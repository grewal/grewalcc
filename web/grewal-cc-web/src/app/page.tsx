import { Suspense } from 'react';
import { cookies } from 'next/headers';
import Header from '@/components/Header';
import Footer from '@/components/Footer';
import IpInfo from '@/components/IpInfo';
import IpInfoShell from '@/components/IpInfoShell';
import LoginForm from '@/components/LoginForm';
import LogoutButton from '@/components/LogoutButton';

// This User type must match the UserResponse from your Rust service
interface User {
  id: string;
  username: string;
  email: string;
  roles: string[];
}

export default async function HomePage() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;

  let user: User | null = null;

  if (authToken) {
    // This logic calls the backend service directly via the dev tunnel or prod internal network
    const authServiceUrl = process.env.AUTH_SERVICE_INTERNAL_URL || 'http://127.0.0.1:3001/auth/me';
    try {
      const res = await fetch(authServiceUrl, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
        cache: 'no-store',
      });

      if (res.ok) {
        // The /me route returns the user object directly
        user = await res.json();
      } else {
        console.error(`Session validation failed, status: ${res.status}`);
      }
    } catch (error) {
      console.error(`Error during user session fetch:`, error);
    }
  }
  
  return (
    <>
      <Header />
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl font-bold mb-4 text-balance">
            Welcome to Grewal.cc
          </h1>
          
          {user ? (
            <p className="text-lg text-gray-300 mb-10">
              Welcome back, <span className="font-bold text-blue-400">{user.username}</span>!
            </p>
          ) : (
            <p className="text-gray-400 mb-10">
              A full-stack, multi-language, cloud-native application playground.
            </p>
          )}

          <div className="mb-12">
            {user ? <LogoutButton /> : <LoginForm />}
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
              Your Connection Information
            </h2>
            <Suspense fallback={<IpInfoShell />}>
              <IpInfo />
            </Suspense>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}