import { Suspense } from 'react';
import Header from '@/components/Header';
import Footer from '@/components/Footer';
import IpInfo from '@/components/IpInfo';
import IpInfoShell from '@/components/IpInfoShell';

export default function HomePage() {
  return (
    <>
      <Header />
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto text-center">
          <h1 className="text-4xl font-bold mb-8 text-balance">
            Welcome to Grewal.cc
          </h1>
          
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-200 dark:border-gray-700">
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
