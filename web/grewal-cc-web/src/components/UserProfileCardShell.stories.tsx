import type { Meta, StoryObj } from '@storybook/react';
import { UserProfileCardShell } from './UserProfileCardShell';

const meta: Meta<typeof UserProfileCardShell> = {
  title: 'Components/UserProfileCardShell',
  component: UserProfileCardShell,
  parameters: {
    layout: 'centered',
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};
