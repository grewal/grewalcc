import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import Header from '@/components/Header';
import Footer from '@/components/Footer';

// We can reuse the User type definition
interface User {
  user_id: string; // From the JWT claims
  username: string;
  email: string;
  roles: string[];
}

// This is the same core logic from before, now repurposed for this page
async function getAuthenticatedUser(token: string | undefined): Promise<User | null> {
  if (!token) {
    return null;
  }

  const apiRouteUrl = 'http://localhost:3000/api/auth/me';

  try {
    const res = await fetch(apiRouteUrl, {
      headers: { 'Cookie': `grewal-cc-auth-token=${token}` },
      cache: 'no-store',
    });

    if (!res.ok) {
      return null;
    }
    return res.json();
  } catch (error) {
    console.error('Error in getAuthenticatedUser:', error);
    return null;
  }
}

export default async function ProfilePage() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;

  const user = await getAuthenticatedUser(authToken);

  // This is the protection for the route.
  // If we couldn't get a user, redirect to the homepage.
  if (!user) {
    redirect('/');
  }

  return (
    <>
      <Header />
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold mb-4">User Profile</h1>
          <p className="text-gray-400 mb-8">This is a protected page. You can only see this if you are logged in.</p>
          
          <div className="bg-gray-800 p-4 rounded-lg">
            <h2 className="text-xl font-semibold mb-2">Raw User Data:</h2>
            {/* Displaying raw JSON to verify data fetching works */}
            <pre className="text-left bg-gray-900 p-4 rounded text-sm whitespace-pre-wrap">
              {JSON.stringify(user, null, 2)}
            </pre>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
