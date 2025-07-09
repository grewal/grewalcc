import init, { FluidSimulation } from '/simulation/grewalcc_fluid_simulation.js';

let simulation = null;
let wasmMemory = null;
let workerState = 'UNINITIALIZED';
let lastTimestamp = 0;

let speedMultiplier = 1.0;
let quality = 'medium';
const qualitySettings = {
  low: { resolutionScale: 0.5 },
  medium: { resolutionScale: 0.75 },
  high: { resolutionScale: 1.0 },
};

let frameCount = 0;
let lastMetricsUpdateTime = 0;

self.onmessage = async (event) => {
  const { type, payload } = event.data;

  switch (type) {
    case 'INIT':
      await handleInit(payload);
      break;
    case 'TICK':
      handleTick(payload);
      break;
    case 'PAUSE':
      if (workerState === 'READY') {
        workerState = 'PAUSED';
        console.log("[FluidWorker] Paused.");
      }
      break;
    case 'RESUME':
      if (workerState === 'PAUSED') {
        workerState = 'READY';
        lastTimestamp = performance.now();
        console.log("[FluidWorker] Resumed.");
      }
      break;
    case 'SET_QUALITY':
      if (simulation && payload.quality in qualitySettings) {
        quality = payload.quality;
        simulation.resize(
          Math.floor(payload.width * qualitySettings[quality].resolutionScale),
          Math.floor(payload.height * qualitySettings[quality].resolutionScale)
        );
      }
      break;
    case 'SET_SPEED':
      if (payload.speed > 0) {
        speedMultiplier = payload.speed;
      }
      break;
    case 'STOP':
      await handleStop();
      break;
    default:
      console.warn(`[FluidWorker] Unknown message type: ${type}`);
  }
};

async function handleInit(payload) {
  if (workerState !== 'UNINITIALIZED') await handleStop();

  workerState = 'INITIALIZING';
  console.log("[FluidWorker] Initializing simulation...");

  try {
    const wasm = await init();
    wasmMemory = wasm.memory;

    quality = payload.quality || 'medium';
    const resScale = qualitySettings[quality].resolutionScale;

    simulation = new FluidSimulation(
      Math.floor(payload.width * resScale),
      Math.floor(payload.height * resScale)
    );

    lastTimestamp = performance.now();
    lastMetricsUpdateTime = lastTimestamp;
    workerState = 'READY';

    self.postMessage({ type: 'READY' });
  } catch (e) {
    console.error("[FluidWorker] WASM initialization failed:", e);
    handleFatalError('WASM init failed');
  }
}

function handleTick(timestamp) {
  if (workerState !== 'READY') return;

  let deltaTime = (timestamp - lastTimestamp) / 1000.0;
  lastTimestamp = timestamp;

  if (deltaTime > 0) {
    simulation.compute_frame(deltaTime * speedMultiplier);
  }

  const buffer = new Uint8Array(
    wasmMemory.buffer,
    simulation.buffer_ptr(),
    simulation.buffer_len()
  );

  const frameCopy = buffer.slice(); // Transferable copy

  self.postMessage(
    {
      type: 'RENDER',
      payload: { frame: frameCopy.buffer }
    },
    [frameCopy.buffer]
  );

  frameCount++;
  if (timestamp - lastMetricsUpdateTime >= 1000) {
    const fps = frameCount;
    frameCount = 0;
    lastMetricsUpdateTime = timestamp;

    self.postMessage({
      type: 'METRICS',
      payload: { fps, quality, speed: speedMultiplier }
    });
  }
}

async function handleStop() {
  workerState = 'STOPPING';
  if (simulation) {
    simulation.free();
  }
  simulation = null;
  wasmMemory = null;
  workerState = 'UNINITIALIZED';
}

function handleFatalError(message) {
  self.postMessage({ type: 'FATAL_ERROR', payload: message });
  handleStop();
  self.close();
}

