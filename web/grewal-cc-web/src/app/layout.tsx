import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { IpUaDisplay } from '@/components/IpUaDisplay';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'grewal.cc',
  description: 'Professional Software Engineering Portfolio',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        {children}
        <footer className="bg-gray-800 text-white p-4 text-center">
          <p>© 2025 Grewal.cc. All Rights Reserved.</p>
          <IpUaDisplay />
        </footer>
      </body>
    </html>
  );
}
