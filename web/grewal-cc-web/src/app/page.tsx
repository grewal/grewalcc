// File: web/grewal-cc-web/src/app/page.tsx

import { Suspense } from 'react';
import Header from '@/components/Header';
import Footer from '@/components/Footer';
import IpInfo from '@/components/IpInfo';
import IpInfoShell from '@/components/IpInfoShell';
import LoginForm from '@/components/LoginForm';

export default function HomePage() {
  return (
    <>
      <Header />
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl font-bold mb-4 text-balance">
            Welcome to Grewal.cc
          </h1>
          <p className="text-gray-400 mb-10">
            A full-stack, multi-language, cloud-native application playground.
          </p>

          {/* --- RENDER THE LOGIN FORM COMPONENT --- */}
          <div className="mb-12">
            <LoginForm />
          </div>
          {/* -------------------------------------- */}

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
