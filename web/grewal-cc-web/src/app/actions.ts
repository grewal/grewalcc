'use server';

// Import the 'headers' function from Next.js to access request headers.
import { headers } from 'next/headers';

// CORRECTED: Import the *actual* exported function from our client.
import { getHomeGeneral } from '@/services/grewalccClient';

export async function fetchIpUaDataAction() {
  try {
    // Get the headers from the incoming request to the Server Action.
    const requestHeaders = headers();
    
    // Extract the specific headers we need.
    // The 'x-forwarded-for' header will contain the real client IP.
    // Provide sensible fallbacks if the headers are missing.
    const clientIp = requestHeaders.get('x-forwarded-for') || 'IP Not Found';
    const clientUserAgent = requestHeaders.get('user-agent') || 'UA Not Found';

    // Call the correct function, 'getHomeGeneral', and pass it the required userInfo object.
    const result = await getHomeGeneral({ clientIp, clientUserAgent });
    
    // Return the data from the gRPC service.
    return {
      ip: result.remoteIp,
      userAgent: result.userAgent,
    };
  } catch (error: any) {
    console.error('Server Action failed to fetch IP/UA data:', error);
    return {
      ip: 'Error',
      userAgent: 'Could not connect to gRPC service.',
      error: error.message,
    };
  }
}
