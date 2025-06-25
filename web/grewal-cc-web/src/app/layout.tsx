import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Grewal.cc',
  description: 'A Live Engineering Portfolio',
  viewport: 'width=device-width, initial-scale=1',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col bg-white text-gray-900 dark:bg-gray-900 dark:text-gray-100">
        {children}
      </body>
    </html>
  );
}
