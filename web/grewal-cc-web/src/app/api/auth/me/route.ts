import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function GET(request: Request) {
  try {
    // 1. Read the session token from the incoming request's cookies.
    const cookieStore = cookies();
    const tokenCookie = cookieStore.get('grewal-cc-auth-token');

    // 2. If no token exists, the user is not authenticated.
    if (!tokenCookie) {
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }

    const token = tokenCookie.value;
    const authServiceUrl = process.env.AUTH_SERVICE_URL;

    // 3. Forward the token to the backend auth service for validation.
    const apiRes = await fetch(`${authServiceUrl}/auth/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      },
    });
    
    const data = await apiRes.json();

    // 4. Forward backend service errors to client
    if (!apiRes.ok) {
      return NextResponse.json(data, { status: apiRes.status });
    }

    // 5. Otherwise backend service responds with success, return user data
    return NextResponse.json(data, { status: 200 });

  } catch (error: any) {
    console.error('Me API route error:', error);
    return NextResponse.json(
      { message: error.message || 'An internal server error occurred.' },
      { status: 500 }
    );
  }
}
