import { Agent } from 'undici';

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  roles: string[];
}

export async function getAuthenticatedUser(
  authToken: string | undefined
): Promise<AuthenticatedUser | null> {
  if (!authToken) {
    return null;
  }

  const authServiceUrl = process.env.AUTH_SERVICE_URL;
  if (!authServiceUrl) {
    console.error('AUTH_SERVICE_URL is not defined for session check.');
    return null;
  }

  try {
    const fetchOptions: RequestInit = {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    };

    if (process.env.NODE_ENV === 'development') {
      (fetchOptions as any).dispatcher = new Agent({
        connect: {
          rejectUnauthorized: false,
        },
      });
    }

    const response = await fetch(`${authServiceUrl}/auth/me`, fetchOptions);

    if (response.status === 401) {
      console.log('Session validation failed, status: 401');
      return null;
    }

    if (!response.ok) {
      console.error(`Session validation failed with status: ${response.status}`);
      return null;
    }

    const rawUserData = await response.json();

    const userData: AuthenticatedUser = {
      id: rawUserData.user_id,
      username: rawUserData.username,
      email: rawUserData.email,
      roles: rawUserData.roles,
    };

    return userData;
  } catch (error) {
    console.error('Failed to render user information:', error);
    return null;
  }
}
