import { GeneralRequest, GeneralResponse } from '@/lib/grpc/home_general_pb';
import { HomeGeneralClient } from '@/lib/grpc/home_general_grpc_pb';
import * as grpc from '@grpc/grpc-js';

// --- Configuration ---
// In a real production app, this would come from environment variables.
// Docker's internal DNS will resolve 'grewalcc' to the correct container IP.
const BACKEND_ADDRESS = 'grewalcc:50051';

// --- Define the data structure for our application ---
export interface HomeData {
  remoteIp: string;
  userAgent: string;
}

// --- Create a reusable, lazy-loaded gRPC client instance ---
// This prevents creating a new connection for every request, which is inefficient.
let client: HomeGeneralClient | null = null;

function getClient(): HomeGeneralClient {
  if (!client) {
    console.log(`[gRPC Client] Creating new client connection to ${BACKEND_ADDRESS}`);
    client = new HomeGeneralClient(
      BACKEND_ADDRESS,
      grpc.credentials.createInsecure() // Use insecure credentials for internal, service-to-service communication
    );
  }
  return client;
}

// --- The main data-fetching function ---
// This is the function our server components will call.
// It wraps the old-style callback-based gRPC call in a modern async/await Promise.
export async function getHomeData(
  // We will pass the original request headers from the server component
  // to propagate the user's IP and User-Agent.
  metadata: grpc.Metadata = new grpc.Metadata()
): Promise<HomeData> {
  return new Promise((resolve, reject) => {
    const grpcClient = getClient();
    const request = new GeneralRequest();

    // Set a deadline for the RPC call. Crucial for preventing hangs.
    const deadline = new Date();
    deadline.setSeconds(deadline.getSeconds() + 5); // 5-second timeout

    console.log('[gRPC Client] Making getHomeGeneral RPC call...');

    grpcClient.getHomeGeneral(
      request,
      metadata, // Pass headers/metadata to the backend
      { deadline },
      (error: grpc.ServiceError | null, response: GeneralResponse) => {
        if (error) {
          console.error(`[gRPC Client] RPC Error: code=${error.code}, details="${error.details}"`);
          // In a real app, you might want to destroy the client on certain errors
          // to force a reconnection on the next call.
          // if (error.code === grpc.status.UNAVAILABLE) { client = null; }
          return reject(new Error(`[gRPC Error] ${error.details}`));
        }
        if (response) {
          console.log('[gRPC Client] RPC Success. Received response.');
          const data: HomeData = {
            remoteIp: response.getRemoteIp(),
            userAgent: response.getUserAgent(),
          };
          resolve(data);
        } else {
          reject(new Error('Received null response from backend without an error'));
        }
      }
    );
  });
}
