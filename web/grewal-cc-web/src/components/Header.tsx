'use client';

import Link from 'next/link';
import LogoutButton from './LogoutButton';
import { LoginModal } from './LoginModal';

interface HeaderProps {
  isLoggedIn: boolean;
}

export function Header({ isLoggedIn }: HeaderProps) {
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
            <LoginModal />
          )}
        </div>
      </nav>
    </header>
  );
}
