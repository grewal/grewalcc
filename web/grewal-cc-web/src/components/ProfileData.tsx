import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getAuthenticatedUser } from '@/lib/auth/session';
import { UserProfileCard } from './UserProfileCard';

export async function ProfileData() {
  // 1. Get the auth token from the cookie store.
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;

  // 2. Guard the route: if no token, redirect.
  if (!authToken) {
    redirect('/?login=true');
  }

  // 3. Fetch the user's data using the token.
  const user = await getAuthenticatedUser(authToken);

  // 4. Guard the route: if token is invalid or user fetch fails, redirect.
  if (!user) {
    redirect('/?login=true');
  }

  // 5. If successful, render the final UI component with the fetched data.
  return <UserProfileCard user={user} />;
}
