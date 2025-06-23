import { getHomeData, HomeData } from '@/services/grewalccClient';
import { headers } from 'next/headers';
import * as grpc from '@grpc/grpc-js';

// This is an async React Server Component (RSC).
// The 'async' keyword is the magic that enables data fetching directly within the component.
export default async function IpInfo() {
  // 1. Prepare Metadata for the gRPC call
  // Next.js provides a `headers()` function to access the incoming request headers on the server.
  const headersList = headers();
  const userAgent = headersList.get('user-agent') || 'Unknown';
  
  // The x-forwarded-for header can be a comma-separated list of IPs.
  // We are interested in the original client IP, which is typically the first one.
  const xForwardedFor = headersList.get('x-forwarded-for');
  const clientIp = xForwardedFor ? xForwardedFor.split(',')[0].trim() : 'Unknown';

  // We create gRPC Metadata to pass these headers to the backend.
  // The C++ gRPC server will be able to read these key-value pairs.
  const metadata = new grpc.Metadata();
  metadata.set('x-forwarded-for', clientIp);
  metadata.set('user-agent', userAgent);
  
  // 2. Fetch the data
  // We simply 'await' our service function. React's renderer will automatically
  // handle the suspension and resumption of this component.
  // We add a try/catch block for resilience. If the backend call fails,
  // we can render an error state instead of crashing the page.
  let data: HomeData;
  try {
    data = await getHomeData(metadata);
  } catch (error) {
    console.error("Failed to fetch home data:", error);
    // Render a user-friendly error state if the fetch fails
    return (
      <div className="mt-4 p-4 border border-red-400 bg-red-100 text-red-700 rounded">
        <p className="font-bold">Error:</p>
        <p>Could not load dynamic data from the backend.</p>
      </div>
    );
  }

  // 3. Render the successful UI
  return (
    <div className="mt-4 p-4 border border-gray-200 rounded-lg bg-gray-50 dark:border-gray-700 dark:bg-gray-800">
      <h2 className="text-lg font-semibold text-gray-700 dark:text-gray-200">Your Connection Details:</h2>
      <div className="mt-2 space-y-1 text-sm text-gray-600 dark:text-gray-400">
        <p>
          <span className="font-medium text-gray-900 dark:text-white">IP Address:</span> {data.remoteIp}
        </p>
        <p>
          <span className="font-medium text-gray-900 dark:text-white">User Agent:</span> {data.userAgent}
        </p>
      </div>
    </div>
  );
}
