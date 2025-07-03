import type { Meta, StoryObj } from '@storybook/react';
import { useState } from 'react';
import { Modal } from './Modal';
import { Button } from './Button';

const meta: Meta<typeof Modal> = {
  title: 'Components/Modal',
  component: Modal,
  parameters: {
    layout: 'centered',
  },
  argTypes: {
    isOpen: { control: 'boolean' },
    title: { control: 'text' },
    onClose: { action: 'closed' },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

const ModalTemplate: Story = {
  render: (args) => {
    const [isOpen, setIsOpen] = useState(args.isOpen);

    const handleClose = () => {
      args.onClose();
      setIsOpen(false);
    };

    return (
      <>
        <Button onClick={() => setIsOpen(true)}>Open Modal</Button>
        <Modal {...args} isOpen={isOpen} onClose={handleClose}>
          <p>This is the content of the modal. It can be any React node.</p>
          <div className="mt-6 flex justify-end space-x-4">
            <Button variant="secondary" onClick={handleClose}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleClose}>
              Confirm
            </Button>
          </div>
        </Modal>
      </>
    );
  },
};

export const Closed: Story = {
  ...ModalTemplate,
  args: {
    isOpen: false,
    title: 'Confirmation Required',
  },
};

export const Open: Story = {
  ...ModalTemplate,
  args: {
    ...Closed.args,
    isOpen: true,
  },
};
