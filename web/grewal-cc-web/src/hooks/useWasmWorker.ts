'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

export type WorkerState = 'LOADING' | 'READY' | 'ERROR';

export function useWasmWorker(workerPath: string) {
  const workerRef = useRef<Worker | null>(null);
  const [workerState, setWorkerState] = useState<WorkerState>('LOADING');
  const [lastMessage, setLastMessage] = useState<any>(null);
  const [frameBuffer, setFrameBuffer] = useState<ArrayBuffer | null>(null);

  useEffect(() => {
    let isMounted = true;
    const worker = new Worker(workerPath, { type: 'module' });
    workerRef.current = worker;

    worker.onmessage = (event) => {
      if (!isMounted) return;

      const { type, payload } = event.data;

      if (type === 'READY') {
        setWorkerState('READY');
      } else if (type === 'RENDER') {
        setFrameBuffer(payload?.frame ?? null);
      } else if (type === 'METRICS') {
        // Optional: pass to caller
      } else if (type === 'FATAL_ERROR') {
        setWorkerState('ERROR');
      }

      setLastMessage(event.data);
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

  return { workerState, postMessage, lastMessage, frameBuffer };
}

