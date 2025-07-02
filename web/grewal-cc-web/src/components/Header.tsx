import { cookies } from 'next/headers';
import Link from 'next/link';
import LogoutButton from './LogoutButton'; 

export async function Header() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;
  const isLoggedIn = !!authToken;

  return (
    <header className="bg-gray-800 text-white p-4">
      <nav className="container mx-auto flex justify-between items-center">
        <div className="text-lg font-bold">
          <Link href="/" className="hover:text-gray-300">
            grewal.cc
          </Link>
        </div>
        <div className="flex items-center space-x-4">
          <Link href="/" className="hover:text-gray-300">
            Home
          </Link>
          {isLoggedIn ? (
            <>
              <Link href="/profile" className="hover:text-gray-300">
                Profile
              </Link>
              <LogoutButton />
            </>
          ) : (
            <Link
              href="/login"
              className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded"
            >
              Login
            </Link>
          )}
        </div>
      </nav>
    </header>
  );
}
