import type { Meta, StoryObj } from '@storybook/react';
import UserProfileCardShell from './UserProfileCardShell';

const meta: Meta<typeof UserProfileCardShell> = {
  title: 'Components/UserProfileCardShell',
  component: UserProfileCardShell,
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof UserProfileCardShell>;

export const Default: Story = {};
