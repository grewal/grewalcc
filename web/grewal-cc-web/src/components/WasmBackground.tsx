'use client';

import { useEffect, useRef, useCallback, useState } from 'react';
import { useWasmWorker } from '@/hooks/useWasmWorker';
import { Button, Dropdown, DropdownTrigger, DropdownMenu, DropdownItem, Spinner } from '@nextui-org/react';
import { FaPlay, FaPause, FaTachometerAlt, FaFlask, FaExclamationTriangle } from 'react-icons/fa';

const StatusDisplay = ({ metrics }: { metrics: any }) => (
  <div className="fixed top-20 right-5 bg-black/60 text-white p-4 rounded-lg font-mono text-xs z-20 backdrop-blur-md border border-white/20 shadow-lg">
    <div>Status: <span className={`font-bold ${metrics.status === 'Ready' ? 'text-green-400' : 'text-yellow-400'}`}>{metrics.status || 'Loading...'}</span></div>
    <div>FPS: <span className="font-bold text-green-400">{metrics.fps || 0}</span></div>
    <div>Quality: <span className="font-bold capitalize text-green-400">{metrics.quality || 'N/A'}</span></div>
    <div>Speed: <span className="font-bold text-green-400">{metrics.speed || 0}x</span></div>
  </div>
);

const Controls = ({ onCommand, isReady }: { onCommand: (cmd: object) => void; isReady: boolean }) => {
  const [isPaused, setIsPaused] = useState(false);

  const handlePauseToggle = () => {
    onCommand({ type: isPaused ? 'RESUME' : 'PAUSE' });
    setIsPaused(!isPaused);
  };

  return (
    <div className="fixed bottom-5 left-1/2 -translate-x-1/2 flex gap-3 z-20">
      <Button isIconOnly onPress={handlePauseToggle} isDisabled={!isReady} variant="flat" className="bg-white/10 backdrop-blur-sm text-white border-white/20 border">
        {isPaused ? <FaPlay /> : <FaPause />}
      </Button>
      <Dropdown>
        <DropdownTrigger>
          <Button isDisabled={!isReady} variant="flat" endContent={<FaFlask />} className="bg-white/10 backdrop-blur-sm text-white border-white/20 border">Quality</Button>
        </DropdownTrigger>
        <DropdownMenu
          aria-label="Quality"
          onAction={(key) => onCommand({ type: 'SET_QUALITY', payload: { quality: key, width: window.innerWidth, height: window.innerHeight } })}
        >
          <DropdownItem key="low">Low</DropdownItem>
          <DropdownItem key="medium">Medium</DropdownItem>
          <DropdownItem key="high">High</DropdownItem>
        </DropdownMenu>
      </Dropdown>
      <Dropdown>
        <DropdownTrigger>
          <Button isDisabled={!isReady} variant="flat" endContent={<FaTachometerAlt />} className="bg-white/10 backdrop-blur-sm text-white border-white/20 border">Speed</Button>
        </DropdownTrigger>
        <DropdownMenu
          aria-label="Speed"
          onAction={(key) => onCommand({ type: 'SET_SPEED', payload: { speed: parseFloat(key as string) } })}
        >
          <DropdownItem key="0.5">0.5x</DropdownItem>
          <DropdownItem key="1.0">1.0x</DropdownItem>
          <DropdownItem key="2.0">2.0x</DropdownItem>
        </DropdownMenu>
      </Dropdown>
    </div>
  );
};

export function WasmBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameIdRef = useRef<number | null>(null);
  const imageDataRef = useRef<ImageData | null>(null);

  const { workerState, postMessage, lastMessage } = useWasmWorker('/fluid-worker.js');

  const [metrics, setMetrics] = useState({ status: 'Loading', fps: 0, quality: 'medium', speed: 1.0 });

  const renderLoop = useCallback(() => {
    postMessage({ type: 'TICK', payload: performance.now() });
    animationFrameIdRef.current = requestAnimationFrame(renderLoop);
  }, [postMessage]);

  useEffect(() => {
    if (workerState === 'READY' && !animationFrameIdRef.current) {
      animationFrameIdRef.current = requestAnimationFrame(renderLoop);
    }
    return () => {
      if (animationFrameIdRef.current) {
        cancelAnimationFrame(animationFrameIdRef.current);
        animationFrameIdRef.current = null;
      }
    };
  }, [workerState, renderLoop]);

  useEffect(() => {
    if (!lastMessage) return;

    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d', { alpha: false, desynchronized: true });

    if (lastMessage.type === 'RENDER' && canvas && ctx) {
      const frame = new Uint8ClampedArray(lastMessage.payload.frame);
      const { width, height } = canvas;

      if (!imageDataRef.current || imageDataRef.current.width !== width || imageDataRef.current.height !== height) {
        imageDataRef.current = new ImageData(width, height);
      }

      imageDataRef.current.data.set(frame);
      ctx.putImageData(imageDataRef.current, 0, 0);
    } else if (lastMessage.type === 'METRICS') {
      setMetrics(prev => ({ ...prev, ...lastMessage.payload }));
    } else if (lastMessage.type === 'READY') {
      setMetrics(prev => ({ ...prev, status: 'Ready' }));
    } else if (lastMessage.type === 'FATAL_ERROR') {
      setMetrics(prev => ({ ...prev, status: 'Error' }));
    }
  }, [lastMessage]);

  useEffect(() => {
    let resizeTimeout: NodeJS.Timeout;
    const handleResize = () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const width = window.innerWidth;
        const height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
        postMessage({ type: 'INIT', payload: { width, height, quality: metrics.quality } });
      }, 150);
    };

    window.addEventListener('resize', handleResize);
    handleResize();

    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(resizeTimeout);
    };
  }, [postMessage, metrics.quality]);

  return (
    <>
      <div className="fixed top-0 left-0 w-full h-full -z-10">
        <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-black to-gray-800" />
        <canvas
          ref={canvasRef}
          className={`absolute inset-0 transition-opacity duration-1000 ${
            workerState === 'READY' ? 'opacity-100' : 'opacity-0'
          }`}
        />
      </div>

      {workerState === 'LOADING' && (
        <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-white z-20 flex flex-col items-center gap-4">
          <Spinner color="white" />
          <span>Loading Simulation...</span>
        </div>
      )}
      {workerState === 'ERROR' && (
        <div className="fixed top-20 right-5 bg-red-900/50 text-white p-4 rounded-lg font-mono text-xs z-20 backdrop-blur-md border border-red-500/50 flex items-center gap-2">
          <FaExclamationTriangle className="text-red-400" />
          <span>Simulation Error</span>
        </div>
      )}
      <StatusDisplay metrics={metrics} />
      <Controls onCommand={postMessage} isReady={workerState === 'READY'} />
    </>
  );
}

