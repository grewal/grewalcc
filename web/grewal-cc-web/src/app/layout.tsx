// web/grewal-cc-web/src/app/layout.tsx

import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { IpUaDisplay } from '@/components/IpUaDisplay';
import { cookies } from 'next/headers';
import { Header } from '@/components/Header';
import { Providers } from './providers';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'grewal.cc',
  description: 'A Full-Stack Playground by Monty Grewal',
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;
  const isLoggedIn = !!authToken;

  return (
    <html lang="en" className='dark'>
      <body className={inter.className}>
        <Providers>
          <Header isLoggedIn={isLoggedIn} />
          <main>
            {children}
          </main>
          <footer className="w-full p-4 text-center">
            <p>© 2025 Grewal.cc. All Rights Reserved.</p>
            <IpUaDisplay />
          </footer>
        </Providers>
      </body>
    </html>
  );
}
