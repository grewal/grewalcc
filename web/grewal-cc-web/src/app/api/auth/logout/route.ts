import { NextResponse } from 'next/server';
import { serialize } from 'cookie';

export async function POST(request: Request) {

  const serializedCookie = serialize('grewal-cc-auth-token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict',
    maxAge: -1, // Set maxAge to a negative number to expire immediately
    path: '/',
  });

  return NextResponse.json(
    { success: true, message: 'Logout successful' },
    {
      status: 200,
      headers: { 'Set-Cookie': serializedCookie },
    }
  );
}
