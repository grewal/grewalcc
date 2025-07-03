import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { getAuthenticatedUser } from '@/lib/auth/session';
import { UserProfileCard } from './UserProfileCard';

export async function ProfileData() {
  const cookieStore = cookies();
  const authToken = cookieStore.get('grewal-cc-auth-token')?.value;

  if (!authToken) {
    redirect('/?login=true');
  }

  const user = await getAuthenticatedUser(authToken);

  if (!user) {
    redirect('/?login=true');
  }
  
  return <UserProfileCard user={user} />;
}
