import { Suspense } from 'react';
import IpInfo from '@/components/IpInfo';
import IpInfoSkeleton from '@/components/IpInfoSkeleton';

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm lg:flex">
        <p className="fixed left-0 top-0 flex w-full justify-center border-b border-gray-300 bg-gradient-to-b from-zinc-200 pb-6 pt-8 backdrop-blur-2xl dark:border-neutral-800 dark:bg-zinc-800/30 dark:from-inherit lg:static lg:w-auto  lg:rounded-xl lg:border lg:bg-gray-200 lg:p-4 lg:dark:bg-zinc-800/30">
          Welcome to 
          <code className="font-mono font-bold">grewal.cc</code>
        </p>
        <div className="fixed bottom-0 left-0 flex h-48 w-full items-end justify-center bg-gradient-to-t from-white via-white dark:from-black dark:via-black lg:static lg:size-auto lg:bg-none">
          {/* Your Vercel logo or other footer content can go here */}
        </div>
      </div>

      <div className="relative z-[-1] flex place-items-center">
        {/* Main content area */}
        <div className="text-center">
          <h1 className="text-4xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
            Under Construction
          </h1>
          <p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
            This site is a live portfolio showcasing advanced DevOps, Cloud-Native Engineering, and Full-Stack Development.
          </p>
          
          {/* This is the magic! */}
          <Suspense fallback={<IpInfoSkeleton />}>
            <IpInfo />
          </Suspense>

        </div>
      </div>

      <div className="mb-32 grid text-center lg:mb-0 lg:w-full lg:max-w-5xl lg:grid-cols-4 lg:text-left">
        {/* Your link cards or other content can go here */}
      </div>
    </main>
  );
}
