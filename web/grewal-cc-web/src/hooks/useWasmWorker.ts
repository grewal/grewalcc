// web/grewal-cc-web/src/hooks/useWasmWorker.ts
'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

export type WorkerState = 'LOADING' | 'READY' | 'ERROR';

// This hook now purely manages the worker's lifecycle and communication channel.
export function useWasmWorker(workerPath: string) {
  const workerRef = useRef<Worker | null>(null);
  const [workerState, setWorkerState] = useState<WorkerState>('LOADING');
  const [lastMessage, setLastMessage] = useState<any>(null);

  useEffect(() => {
    let isMounted = true;
    const worker = new Worker(workerPath);
    workerRef.current = worker;
    setWorkerState('LOADING');

    worker.onmessage = (event) => {
      if (!isMounted) return;
      setLastMessage(event.data);
      
      // Update state based on messages
      const { type } = event.data;
      if (type === 'READY') setWorkerState('READY');
      if (type === 'ERROR' || type === 'FATAL_ERROR') setWorkerState('ERROR');
    };

    worker.onerror = (error) => {
      if (!isMounted) return;
      console.error("Unhandled error in WasmWorker hook:", error);
      setWorkerState('ERROR');
    };

    return () => {
      isMounted = false;
      worker.postMessage({ type: 'STOP' });
      worker.terminate();
    };
  }, [workerPath]);

  const postMessage = useCallback((message: object) => {
    workerRef.current?.postMessage(message);
  }, []);

  return { workerState, postMessage, lastMessage };
}
