import { NextResponse } from 'next/server';
import { Agent } from 'undici';
import { serialize } from 'cookie';
import { revalidatePath } from 'next/cache';

export async function POST(request: Request) {
  const appUrl = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  try {
    const body = await request.formData();
    const username_or_email = body.get('username_or_email');
    const password = body.get('password');

    const authServiceUrl = process.env.AUTH_SERVICE_URL;
    if (!authServiceUrl) {
      throw new Error('AUTH_SERVICE_URL environment variable is not defined.');
    }

    const fetchOptions: RequestInit = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username_or_email, password }),
    };

    if (process.env.NODE_ENV === 'development') {
      (fetchOptions as any).dispatcher = new Agent({
        connect: {
          rejectUnauthorized: false,
        },
      });
    }

    const response = await fetch(`${authServiceUrl}/auth/login`, fetchOptions);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Login failed and failed to parse error response.' }));
      const errorMessage = errorData.message || 'Login failed.';
      const homeUrl = new URL('/', appUrl);
      homeUrl.searchParams.set('error', errorMessage);
      return NextResponse.redirect(homeUrl, 303);
    }
    
    const data = await response.json();
    
    if (!data.access_token) {
        throw new Error('Access token not found in authentication service response.');
    }

    const serializedCookie = serialize('grewal-cc-auth-token', data.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'development',
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 24, // 1 day
    });

    // Force revalidation of authentication-dependent paths
    revalidatePath('/profile');
    revalidatePath('/');

    const redirectUrl = new URL('/profile', appUrl);
    
    const redirectResponse = NextResponse.redirect(redirectUrl, {
      status: 303,
      headers: { 
        'Set-Cookie': serializedCookie,
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      },
    });

    return redirectResponse;

  } catch (error: any) {
    console.error('Login API route error:', error);
    const homeUrl = new URL('/', appUrl);
    homeUrl.searchParams.set('error', 'An internal error occurred.');
    return NextResponse.redirect(homeUrl, 307);
  }
}
