// public/fluid-worker.js

import init, { FluidSimulation } from '/simulation/grewalcc_fluid_simulation.js';

// --- State Machine & Configuration ---
let workerState = 'UNINITIALIZED'; // UNINITIALIZED, INITIALIZING, READY, PAUSED, STOPPING, ERROR
let simulation = null;
let lastTimestamp = 0;

const MAX_CONSECUTIVE_ERRORS = 5;
const MAX_DELTA_TIME_S = 0.1; // Max 100ms jump to prevent visual jarring
let consecutiveErrors = 0;

// --- Main Message Handler ---
self.onmessage = async (event) => {
    const { type, payload } = event.data;

    try {
        switch (type) {
            case 'INIT':
                await handleInit(payload);
                break;
            case 'RESIZE':
                handleResize(payload);
                break;
            case 'TICK':
                handleTick(payload);
                break;
            case 'PAUSE':
                handlePause();
                break;
            case 'RESUME':
                handleResume();
                break;
            case 'STOP':
                await handleStop();
                break;
            default:
                console.warn(`[FluidWorker] Unknown message type: ${type}`);
        }
    } catch (e) {
        console.error(`[FluidWorker] Unhandled error in state ${workerState} for message ${type}:`, e);
        handleFatalError('Unhandled exception in message handler.');
    }
};

// --- State-Aware Handler Functions ---

async function handleInit(payload) {
    if (workerState !== 'UNINITIALIZED' && workerState !== 'ERROR') {
        console.warn(`[FluidWorker] INIT received in invalid state: ${workerState}. Resetting.`);
        await handleStop();
    }
    
    workerState = 'INITIALIZING';
    console.log("[FluidWorker] Initializing simulation...");
    const { width, height } = payload;

    try {
        await init(); // Initialize WASM module
        simulation = new FluidSimulation(width, height);
        lastTimestamp = 0;
        consecutiveErrors = 0;
        workerState = 'READY';
        self.postMessage({ type: 'READY' });
    } catch (e) {
        console.error("[FluidWorker] WASM initialization failed:", e);
        handleFatalError('WASM init failed');
    }
}

function handleResize(payload) {
    if (workerState !== 'READY' && workerState !== 'PAUSED') return;
    
    const { width, height } = payload;
    try {
        simulation.resize(width, height);
    } catch (e) {
        console.error("[FluidWorker] WASM resize failed:", e);
        handleFatalError('WASM resize failed');
    }
}

function handleTick(payload) {
    if (workerState !== 'READY') return;

    const timestamp = payload;
    let deltaTime = (timestamp - lastTimestamp) / 1000.0;
    lastTimestamp = timestamp;

    // Clamp delta to prevent large jumps and avoid churn on micro-deltas.
    if (deltaTime <= 0) return;
    if (deltaTime > MAX_DELTA_TIME_S) {
        console.warn(`[FluidWorker] Large delta time detected (${deltaTime.toFixed(3)}s), clamping to ${MAX_DELTA_TIME_S}s.`);
        deltaTime = MAX_DELTA_TIME_S;
    }

    try {
        simulation.compute_frame(deltaTime);
        consecutiveErrors = 0; // Reset error count on success
    } catch (e) {
        console.error("[FluidWorker] WASM compute_frame failed:", e);
        consecutiveErrors++;
        if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
            handleFatalError('Too many consecutive compute_frame errors.');
        } else {
            self.postMessage({ type: 'ERROR', payload: 'WASM compute_frame failed' });
        }
        return;
    }

    // Post memory location back for rendering
    self.postMessage({
        type: 'RENDER',
        payload: {
            bufferPtr: simulation.buffer_ptr(),
            bufferLen: simulation.buffer_len(),
        }
    });
}

function handlePause() {
    if (workerState !== 'READY') return;
    workerState = 'PAUSED';
    console.log("[FluidWorker] Simulation paused.");
}

function handleResume() {
    if (workerState !== 'PAUSED') return;
    workerState = 'READY';
    lastTimestamp = performance.now(); // Reset timestamp to avoid large jump
    console.log("[FluidWorker] Simulation resumed.");
}

async function handleStop() {
    if (workerState === 'UNINITIALIZED') return;
    
    workerState = 'STOPPING';
    console.log("[FluidWorker] Simulation stopping and freeing memory...");
    if (simulation && simulation.free) {
        simulation.free();
    }
    simulation = null;
    workerState = 'UNINITIALIZED';
}

function handleFatalError(message) {
    console.error(`[FluidWorker] FATAL ERROR: ${message}. Terminating worker.`);
    handleStop();
    workerState = 'ERROR';
    self.postMessage({ type: 'FATAL_ERROR', payload: message });
    self.close(); // Terminate the worker permanently
}
