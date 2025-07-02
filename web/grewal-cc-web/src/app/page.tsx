import { HeroSection } from '@/components/HeroSection';
import { Header } from '@/components/Header';

export default async function HomePage() {
  return (
    <div className="flex flex-col min-h-screen bg-gray-900 text-white">
      {/* 
        The Header component itself is an async Server Component.
      */}
      <Header />
      <main className="flex-grow">
        <HeroSection />
      </main>

      <footer className="bg-gray-800 text-white p-4 text-center">
        <p>© 2025 grewal.cc. All Rights Reserved.</p>
      </footer>
    </div>
  );
}
