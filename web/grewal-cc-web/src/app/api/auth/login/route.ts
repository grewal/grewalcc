import { NextResponse } from 'next/server';
import { serialize } from 'cookie';
import { Agent } from 'undici';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, password } = body;

    const authServiceUrl = process.env.AUTH_SERVICE_URL;

    // --- START OF MODIFICATION ---

    // Define the options for our fetch call
    const fetchOptions: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username_or_email: email, password }),
    };

    if (process.env.NODE_ENV === 'development') {
      const dispatcher = new Agent({
        connect: {
          rejectUnauthorized: false
        }
      });
      (fetchOptions as any).dispatcher = dispatcher;
    }

    // --- END OF MODIFICATION ---

    const apiRes = await fetch(`${authServiceUrl}/auth/login`, fetchOptions);

    if (!apiRes.ok) {
        const errorText = await apiRes.text();
        console.error(`Auth service responded with error: ${apiRes.status} ${errorText}`);
        throw new Error('Authentication failed');
    }

    const data = await apiRes.json();
    const { access_token } = data;

    const serializedCookie = serialize('grewal-cc-auth-token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24 * 7,
      path: '/',
    });

    return new NextResponse(
        JSON.stringify({ success: true, message: 'Login successful' }),
        {
          status: 200,
          headers: { 'Set-Cookie': serializedCookie },
        }
    );

  } catch (error: any) {
    console.error('Login API route error:', error);
    return NextResponse.json(
      { message: error.message || 'An internal server error occurred.' },
      { status: 500 }
    );
  }
}
