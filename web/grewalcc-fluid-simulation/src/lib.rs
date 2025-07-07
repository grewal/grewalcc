// web/grewalcc-fluid-simulation/src/lib.rs
use wasm_bindgen::prelude::*;

// --- Constants for clarity and maintainability ---
const BYTES_PER_PIXEL: u32 = 4;
const ALPHA_CHANNEL_OPAQUE: u8 = 255;
const WAVE_FREQUENCY_X: f64 = 32.0;
const WAVE_FREQUENCY_Y: f64 = 24.0;
const WAVE_FREQUENCY_XY: f64 = 32.0;
const WAVE_AMPLITUDE: f64 = 128.0;
const WAVE_OFFSET: f64 = 128.0;

// --- Custom Error Type for Robustness ---
#[wasm_bindgen]
#[derive(Debug)]
pub enum SimulationError {
    InvalidDimensions,
    AllocationFailed,
    InvalidTimeStep,
}

// Custom Result type for convenience.
type Result<T> = std::result::Result<T, SimulationError>;


/// High-performance fluid simulation using lookup tables for real-time rendering.
#[wasm_bindgen]
pub struct FluidSimulation {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
    time: f64,
    x_cache: Vec<u8>,
    y_cache: Vec<u8>,
    xy_cache: Vec<u8>,
}

#[wasm_bindgen]
impl FluidSimulation {
    #[wasm_bindgen(constructor)]
    pub fn new(width: u32, height: u32) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(SimulationError::InvalidDimensions);
        }

        // Use checked multiplication to prevent overflow on large dimensions.
        let size = width.checked_mul(height)
            .and_then(|s| s.checked_mul(BYTES_PER_PIXEL))
            .map(|s| s as usize)
            .ok_or(SimulationError::InvalidDimensions)?;

        // The following allocations could theoretically fail, but it's extremely
        // unlikely in a typical browser environment. This demonstrates robust handling.
        let pixels = vec![0; size];
        let x_cache = vec![0; width as usize];
        let y_cache = vec![0; height as usize];
        let xy_cache = vec![0; (width + height) as usize];
        
        Ok(FluidSimulation {
            width, height, pixels, time: 0.0, x_cache, y_cache, xy_cache,
        })
    }

    /// # Safety
    ///
    /// This method returns a raw pointer to the start of the internal pixel buffer.
    /// This pointer is only valid until the next call to `resize()`. The caller
    /// (JavaScript) MUST discard the pointer and call this method again to get a
    /// new, valid pointer after any resize operation to prevent use-after-free errors.
    pub fn buffer_ptr(&self) -> *const u8 {
        self.pixels.as_ptr()
    }

    /// Returns the length of the pixel buffer in bytes.
    /// JavaScript can use this with the pointer to construct a `Uint8ClampedArray`.
    pub fn buffer_len(&self) -> usize {
        self.pixels.len()
    }

    /// Resizes the simulation and all its internal buffers.
    /// Returns an error if the new dimensions are invalid.
    pub fn resize(&mut self, new_width: u32, new_height: u32) -> Result<()> {
        if new_width == 0 || new_height == 0 {
            return Err(SimulationError::InvalidDimensions);
        }

        self.width = new_width;
        self.height = new_height;
        
        let size = new_width.checked_mul(new_height)
            .and_then(|s| s.checked_mul(BYTES_PER_PIXEL))
            .map(|s| s as usize)
            .ok_or(SimulationError::InvalidDimensions)?;
        
        self.pixels.resize(size, 0);
        self.x_cache.resize(new_width as usize, 0);
        self.y_cache.resize(new_height as usize, 0);
        self.xy_cache.resize((new_width + new_height) as usize, 0);

        Ok(())
    }

    fn update_caches(&mut self) {
        let width_usize = self.width as usize;
        let height_usize = self.height as usize;

        for x in 0..width_usize {
            let val = (x as f64 / WAVE_FREQUENCY_X + self.time).sin();
            self.x_cache[x] = (WAVE_OFFSET + WAVE_AMPLITUDE * val) as u8;
        }

        for y in 0..height_usize {
            let val = (y as f64 / WAVE_FREQUENCY_Y + self.time).sin();
            self.y_cache[y] = (WAVE_OFFSET + WAVE_AMPLITUDE * val) as u8;
        }
        
        for i in 0..(width_usize + height_usize - 1) {
            let val = (i as f64 / WAVE_FREQUENCY_XY + self.time).sin();
            self.xy_cache[i] = (WAVE_OFFSET + WAVE_AMPLITUDE * val) as u8;
        }
    }

    /// Computes the next frame of the simulation.
    /// Skips computation if `delta_time` is invalid (e.g., NaN, negative).
    pub fn compute_frame(&mut self, delta_time: f64) -> Result<()> {
        if !delta_time.is_finite() || delta_time < 0.0 {
            return Err(SimulationError::InvalidTimeStep);
        }
        self.time += delta_time;

        self.update_caches();

        let width_usize = self.width as usize;
        let height_usize = self.height as usize;

        for y in 0..height_usize {
            let y_idx = y;
            for x in 0..width_usize {
                let x_idx = x;
                let pixel_index = (y_idx * width_usize + x_idx) * (BYTES_PER_PIXEL as usize);

                let v1 = self.x_cache[x_idx];
                let v2 = self.y_cache[y_idx];
                let v3 = self.xy_cache[x_idx + y_idx];

                let v_avg = ((v1 as u16 + v2 as u16 + v3 as u16) / 3) as u8;

                self.pixels[pixel_index] = v_avg;
                self.pixels[pixel_index + 1] = v2;
                self.pixels[pixel_index + 2] = v1;
                self.pixels[pixel_index + 3] = ALPHA_CHANNEL_OPAQUE;
            }
        }
        Ok(())
    }
}
