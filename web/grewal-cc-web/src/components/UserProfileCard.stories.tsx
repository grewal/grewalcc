import type { Meta, StoryObj } from '@storybook/react';
import UserProfileCard from './UserProfileCard';

const meta: Meta<typeof UserProfileCard> = {
  title: 'Components/UserProfileCard',
  component: UserProfileCard,
  tags: ['autodocs'],
  argTypes: {
    user: {
      control: 'object',
      description: 'The user data object to display.',
    },
  },
};

export default meta;
type Story = StoryObj<typeof UserProfileCard>;

const mockUser = {
  user_id: '5d4a8e3b-0f2a-4826-ba81-fc07300c9c91',
  username: 'monty',
  email: 'ygrewal@gmail.com',
  roles: ['user', 'admin', 'beta-tester'],
};

export const Default: Story = {
  args: {
    user: mockUser,
  },
};

export const UserWithLongData: Story = {
  args: {
    user: {
      ...mockUser,
      username: 'a_very_long_username_that_might_break_the_layout',
      email: 'a_similarly_long_and_contrived_email_address@example.com',
      roles: ['user', 'admin', 'beta-tester', 'subscriber', 'power-user', 'moderator'],
    },
  },
};
