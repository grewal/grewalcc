import { NextResponse } from 'next/server';
import { serialize } from 'cookie';
import { revalidatePath } from 'next/cache';

export async function GET(request: Request) {
  const serializedCookie = serialize('grewal-cc-auth-token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict',
    maxAge: -1,
    path: '/',
  });

  // Use explicit environment variable hierarchy with logging
  const appUrl = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
  
  // Log for debugging in production
  console.log('Logout redirect - APP_URL:', process.env.APP_URL);
  console.log('Logout redirect - NEXT_PUBLIC_APP_URL:', process.env.NEXT_PUBLIC_APP_URL);
  console.log('Logout redirect - Using appUrl:', appUrl);
  
  // Force revalidation of authentication-dependent paths
  revalidatePath('/profile');
  revalidatePath('/');

  const redirectUrl = new URL('/', appUrl);

  return NextResponse.redirect(redirectUrl, {
    status: 303,
    headers: { 
      'Set-Cookie': serializedCookie,
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    },
  });
}

export async function POST(request: Request) {
  // Handle POST requests the same way as GET for logout
  return GET(request);
}
