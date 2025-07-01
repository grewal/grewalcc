import { NextResponse } from 'next/server';
import { serialize } from 'cookie';
import { Agent } from 'undici';

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const email = formData.get('email') as string;
    const password = formData.get('password') as string;

    const authServiceUrl = process.env.AUTH_SERVICE_URL;

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

    const apiRes = await fetch(`${authServiceUrl}/auth/login`, fetchOptions);
    const data = await apiRes.json();

    if (!apiRes.ok) {
      const homeUrl = new URL('/', request.url);
      homeUrl.searchParams.set('error', data.message || 'Authentication Failed');
      return NextResponse.redirect(homeUrl);
    }

    const { access_token } = data;

    const serializedCookie = serialize('grewal-cc-auth-token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24 * 7,
      path: '/',
    });
    
    const redirectUrl = new URL('/', request.url);
    return NextResponse.redirect(redirectUrl, {
      status: 303, // See Other
      headers: { 'Set-Cookie': serializedCookie },
    });

  } catch (error: any) {
    console.error('Login API route error:', error);
    const homeUrl = new URL('/', request.url);
    homeUrl.searchParams.set('error', 'An internal error occurred.');
    return NextResponse.redirect(homeUrl);
  }
}
