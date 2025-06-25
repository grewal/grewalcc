// File: web/src/components/Header.tsx
import Link from 'next/link';

export default function Header() {
  return (
    <header className="bg-gray-900 text-white shadow-md">
      <div className="container mx-auto flex justify-between items-center p-4">
        <Link href="/" className="text-xl font-bold hover:text-gray-300">
          Grewal.cc
        </Link>
        <nav className="space-x-6">
          <Link href="/" className="hover:text-gray-300">Home</Link>
          <Link href="/search" className="hover:text-gray-300">Search</Link>
          <Link href="/login" className="hover:text-gray-300">Login</Link>
          <Link href="/register" className="hover:text-gray-300">Register</Link>
        </nav>
      </div>
    </header>
  );
}
