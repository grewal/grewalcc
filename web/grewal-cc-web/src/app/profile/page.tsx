import { Suspense } from 'react';
import { ProfileData } from '@/components/ProfileData';
import { UserProfileCardShell } from '@/components/UserProfileCardShell';

export default function ProfilePage() {
  return (
    <div className="container mx-auto p-4 md:p-8">
      <h1 className="text-3xl font-bold mb-6 text-white">Your Profile</h1>
      <Suspense fallback={<UserProfileCardShell />}>
        <ProfileData />
      </Suspense>
    </div>
  );
}
