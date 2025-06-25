import * as grpc from '@grpc/grpc-js';
import { GeneralRequest, GeneralResponse } from '@/lib/grpc/home_general_pb';
import { HomeGeneralClient } from '@/lib/grpc/home_general_grpc_pb';

const GRPC_SERVICE_URL = process.env.GRPC_SERVICE_URL || 'grewalcc:50051';
export interface HomeData { remoteIp: string; userAgent: string; }
interface UserInfo { clientIp: string; clientUserAgent: string; }
type HomeGeneralClientInstance = InstanceType<typeof HomeGeneralClient>;
let grpcClient: HomeGeneralClientInstance | null = null;

function getClient(): HomeGeneralClientInstance {
  if (!grpcClient) {
    grpcClient = new HomeGeneralClient(GRPC_SERVICE_URL, grpc.credentials.createInsecure());
  }
  return grpcClient;
}

export async function getHomeGeneral(userInfo: UserInfo): Promise<HomeData> {
  return new Promise((resolve, reject) => {
    const client = getClient();
    const request = new GeneralRequest();
    const metadata = new grpc.Metadata();
    metadata.add('x-forwarded-for', userInfo.clientIp);
    metadata.add('x-client-user-agent', userInfo.clientUserAgent);
    const deadline = new Date();
    deadline.setSeconds(deadline.getSeconds() + 5);
    client.getHomeGeneral(request, metadata, { deadline }, (error: grpc.ServiceError | null, response: GeneralResponse) => {
      if (error) return reject(new Error(`gRPC service unavailable: ${error.message}`));
      if (!response) return reject(new Error('Empty response from gRPC service'));
      resolve({ remoteIp: response.getRemoteIp(), userAgent: response.getUserAgent() });
    });
  });
}
