import type { Meta, StoryObj } from '@storybook/react';
import { UserProfileCard } from './UserProfileCard';
import { AuthenticatedUser } from '@/lib/auth/session';

const meta: Meta<typeof UserProfileCard> = {
  title: 'Components/UserProfileCard',
  component: UserProfileCard,
  parameters: {
    layout: 'centered',
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

// Mock user data for the story.
const mockUser: AuthenticatedUser = {
  id: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  username: 'monty_grewal',
  email: 'monty.grewal@example.com',
  roles: ['admin', 'beta-tester', 'subscriber'],
};

const mockUserWithLongData: AuthenticatedUser = {
  ...mockUser,
  username: 'monty_grewal_with_a_very_long_username_to_test_wrapping',
  email: 'monty.grewal.with.a.super.long.email.address.to.check.layout@example.com',
};

export const Default: Story = {
  args: {
    user: mockUser,
  },
};

export const UserWithLongData: Story = {
    args: {
        user: mockUserWithLongData,
    },
};
