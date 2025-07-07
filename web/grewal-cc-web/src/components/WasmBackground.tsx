// web/grewal-cc-web/src/components/WasmBackground.tsx
'use client';

import { useEffect, useRef, useCallback } from 'react';
import { useWasmWorker } from '@/hooks/useWasmWorker';

export function WasmBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameIdRef = useRef<number | null>(null);
  
  // Our clean, reusable hook manages the worker's state and communication.
  const { workerState, postMessage, lastMessage } = useWasmWorker('/fluid-worker.js');

  const renderLoop = useCallback(() => {
    // The loop just sends a TICK message. The worker does the heavy lifting.
    postMessage({ type: 'TICK', payload: performance.now() });
    animationFrameIdRef.current = requestAnimationFrame(renderLoop);
  }, [postMessage]);

  // Effect to manage the render loop based on worker state
  useEffect(() => {
    if (workerState === 'READY') {
      if (animationFrameIdRef.current) cancelAnimationFrame(animationFrameIdRef.current);
      animationFrameIdRef.current = requestAnimationFrame(renderLoop);
    }
    // Cleanup the animation frame if the component unmounts or worker errors
    return () => {
      if (animationFrameIdRef.current) {
        cancelAnimationFrame(animationFrameIdRef.current);
      }
    };
  }, [workerState, renderLoop]);

  // Effect to handle RENDER messages from the worker
  useEffect(() => {
    if (lastMessage?.type === 'RENDER') {
      const { bufferPtr, bufferLen } = lastMessage.payload;
      const canvas = canvasRef.current;
      const ctx = canvas?.getContext('2d');

      // This is the raw memory buffer from the WASM module.
      // We must get a fresh reference as the memory can be resized.
      const wasmMemoryBuffer = (postMessage.__closure__?.workerRef.current as any)
        ?.Module?.wasm?.memory?.buffer;

      if (ctx && wasmMemoryBuffer) {
        // A+++ Optimization: Use createImageBitmap for GPU-accelerated rendering
        const pixels = new Uint8ClampedArray(wasmMemoryBuffer, bufferPtr, bufferLen);
        const imageData = new ImageData(pixels, canvas.width, canvas.height);
        
        createImageBitmap(imageData).then((bitmap) => {
          ctx.drawImage(bitmap, 0, 0);
        });
      }
    }
  }, [lastMessage, postMessage]);

  // Effect for lifecycle management (INIT, RESIZE, PAUSE/RESUME)
  useEffect(() => {
    // Initial INIT message
    postMessage({ type: 'INIT', payload: { width: window.innerWidth, height: window.innerHeight } });

    // A+++ Optimization: Pause simulation when tab is hidden to save battery/CPU
    const handleVisibilityChange = () => {
      if (document.hidden) {
        postMessage({ type: 'PAUSE' });
      } else {
        postMessage({ type: 'RESUME' });
      }
    };
    
    const handleResize = () => {
        if (canvasRef.current) {
            const canvas = canvasRef.current;
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            postMessage({ type: 'RESIZE', payload: { width: canvas.width, height: canvas.height } });
        }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('resize', handleResize);
    handleResize(); // Set initial size

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('resize', handleResize);
    };
  }, [postMessage]);

  return (
    <div className="fixed top-0 left-0 w-full h-full -z-10">
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-black to-gray-800" />
      <canvas
        ref={canvasRef}
        className={`absolute inset-0 transition-opacity duration-1000 ${
          workerState === 'READY' ? 'opacity-100' : 'opacity-0'
        }`}
      />
    </div>
  );
}
