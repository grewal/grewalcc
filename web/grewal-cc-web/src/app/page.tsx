import { Suspense } from 'react';
import { cookies } from 'next/headers';
import Header from '@/components/Header';
import Footer from '@/components/Footer';
import IpInfo from '@/components/IpInfo';
import IpInfoShell from '@/components/IpInfoShell';
import LoginForm from '@/components/LoginForm';
import LogoutButton from '@/components/LogoutButton';

interface User {
  username: string;
  email: string;
}

async function getAuthenticatedUser(token: string | undefined): Promise<User | null> {
  if (!token) {
    return null;
  }
  
  const apiRouteUrl = 'http://grewal-cc-web:3000/api/auth/me';

  try {
    const res = await fetch(apiRouteUrl, {
      headers: {
        'Cookie': `grewal-cc-auth-token=${token}`,
      },
      cache: 'no-store', 
    });

    if (!res.ok) {
      console.error(`Failed to fetch user data, status: ${res.status}`);
      return null;
    }

    const data = await res.json();
    return data;

  } catch (error) {
    console.error(`Error fetching authenticated user from ${apiRouteUrl}:`, error);
    return null;
  }
}

export default async function HomePage() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;
  const user = await getAuthenticatedUser(authToken);
  
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
