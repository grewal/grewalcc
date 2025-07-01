import { Suspense } from 'react';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import Header from '@/components/Header';
import Footer from '@/components/Footer';
import LogoutButton from '@/components/LogoutButton';
import UserProfileCard from '@/components/UserProfileCard';
import UserProfileCardShell from '@/components/UserProfileCardShell';

interface User {
  user_id: string;
  username: string;
  email: string;
  roles: string[];
}

async function ProfileData() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;

  if (!authToken) {
    redirect('/');
  }

  const authServiceUrl = process.env.AUTH_SERVICE_INTERNAL_URL || 'http://127.0.0.1:3001/auth/me';

  try {
    const res = await fetch(authServiceUrl, {
      headers: { 'Authorization': `Bearer ${authToken}` },
      cache: 'no-store',
    });

    if (!res.ok) {
      console.error(`Session validation failed, status: ${res.status}`);
      redirect('/');
    }

    const user: User = await res.json();
    return <UserProfileCard user={user} />;

  } catch (error) {
    console.error(`Error during user session fetch:`, error);
    redirect('/');
  }
}

export default function ProfilePage() {
  return (
    <>
      <Header />
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl font-bold mb-4">User Profile</h1>
          <p className="text-gray-400 mb-8">Your session details are below.</p>
          
          <div className="mb-8">
            <Suspense fallback={<UserProfileCardShell />}>
              <ProfileData />
            </Suspense>
          </div>
          
          <div className="max-w-xs mx-auto">
            <LogoutButton />
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
