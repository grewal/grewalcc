'use client';

import { useState } from 'react';
import { Modal } from './Modal';
import { Button } from './Button';
import LoginForm from './LoginForm';

export function LoginModal() {
  const [isOpen, setIsOpen] = useState(false);

  const openModal = () => setIsOpen(true);
  const closeModal = () => setIsOpen(false);

  return (
    <>
      <Button onClick={openModal}>Login</Button>

      <Modal isOpen={isOpen} onClose={closeModal} title="Member Login">
        <LoginForm />
      </Modal>
    </>
  );
}
