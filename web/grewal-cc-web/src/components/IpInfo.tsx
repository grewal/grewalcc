import { headers } from 'next/headers';
import { getHomeGeneral } from '@/services/grewalccClient';

export default async function IpInfo() {
  const headersList = headers();
  
  // Extract client information from headers, providing sensible fallbacks.
  const clientIp = headersList.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const clientUserAgent = headersList.get('user-agent') || 'unknown';
  
  try {
    // Fetch data from our gRPC service, passing the extracted info.
    const response = await getHomeGeneral({
      clientIp,
      clientUserAgent,
    });
    
    // Render the success UI
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between p-3 bg-blue-50 dark:bg-blue-900/20 rounded border border-blue-200 dark:border-blue-800">
          <span className="text-gray-700 dark:text-gray-300 font-medium">Your IP:</span>
          <span className="text-blue-700 dark:text-blue-300 font-mono text-sm bg-blue-100 dark:bg-blue-900/40 px-2 py-1 rounded">
            {response.remoteIp}
          </span>
        </div>
        
        <div className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/20 rounded border border-green-200 dark:border-green-800">
          <span className="text-gray-700 dark:text-gray-300 font-medium">Your Browser:</span>
          <span className="text-green-700 dark:text-green-300 font-mono text-xs bg-green-100 dark:bg-green-900/40 px-2 py-1 rounded max-w-xs truncate">
            {response.userAgent}
          </span>
        </div>
        
        <div className="flex items-center justify-center pt-2">
          <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
            Connected via gRPC
          </div>
        </div>
      </div>
    );
  } catch (error) {
    // This block executes if the getHomeGeneral promise is rejected.
    console.error('Failed to render user information:', error);
    
    // Render a user-friendly error state
    return (
      <div className="space-y-4">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded border border-red-200 dark:border-red-800">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-red-500 rounded-full mr-3 flex-shrink-0"></div>
            <div>
              <h3 className="text-red-800 dark:text-red-300 font-medium">
                Unable to Fetch Information
              </h3>
              <p className="text-red-600 dark:text-red-400 text-sm mt-1">
                The backend service is temporarily unavailable.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }
}
