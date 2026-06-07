// Web Audio API Synthesizer for UI Sound Effects

let audioCtx = null;
let lastHoverSoundAt = 0;

function getAudioContext() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
  if (audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

const isSoundEnabled = () => {
  return localStorage.getItem('netvisor_sound_enabled') === 'true';
};

export const toggleSound = () => {
  const current = isSoundEnabled();
  localStorage.setItem('netvisor_sound_enabled', !current ? 'true' : 'false');
  return !current;
};

export const getSoundStatus = () => {
  const val = localStorage.getItem('netvisor_sound_enabled');
  if (val === null) {
    // Default to disabled to avoid unexpected startles
    localStorage.setItem('netvisor_sound_enabled', 'false');
    return false;
  }
  return val === 'true';
};

// Play a soft, clean UI click
export const playHoverSound = () => {
  const enabled = isSoundEnabled();
  if (!enabled) return;
  const now = performance.now();
  if (now - lastHoverSoundAt < 90) return;
  lastHoverSoundAt = now;
  try {
    const ctx = getAudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(900, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(1300, ctx.currentTime + 0.04);

    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.04);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.04);
  } catch (e) {
    console.warn('[NetVisor Sound] Web Audio playback failed', e);
  }
};

// Play a nice futuristic warm success sweep
export const playSuccessSound = () => {
  const enabled = isSoundEnabled();
  if (!enabled) return;
  try {
    const ctx = getAudioContext();
    const time = ctx.currentTime;
    
    // First tone
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'triangle';
    osc1.frequency.setValueAtTime(523.25, time); // C5
    osc1.frequency.exponentialRampToValueAtTime(659.25, time + 0.1); // E5
    gain1.gain.setValueAtTime(0.18, time);
    gain1.gain.exponentialRampToValueAtTime(0.0001, time + 0.15);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start();
    osc1.stop(time + 0.15);

    // Second tone slightly delayed
    setTimeout(() => {
      try {
        const time2 = ctx.currentTime;
        const osc2 = ctx.createOscillator();
        const gain2 = ctx.createGain();
        osc2.type = 'triangle';
        osc2.frequency.setValueAtTime(783.99, time2); // G5
        osc2.frequency.exponentialRampToValueAtTime(1046.50, time2 + 0.15); // C6
        gain2.gain.setValueAtTime(0.12, time2);
        gain2.gain.exponentialRampToValueAtTime(0.0001, time2 + 0.25);
        osc2.connect(gain2);
        gain2.connect(ctx.destination);
        osc2.start();
        osc2.stop(time2 + 0.25);
      } catch {
        // Ignore delayed audio playback errors in the secondary tone path.
      }
    }, 80);

  } catch (e) {
    console.warn('[NetVisor Sound] Web Audio playback failed', e);
  }
};

// Play an alert chime for threat/warnings
export const playAlertSound = () => {
  const enabled = isSoundEnabled();
  if (!enabled) return;
  try {
    const ctx = getAudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(150, ctx.currentTime);
    osc.frequency.linearRampToValueAtTime(300, ctx.currentTime + 0.12);
    osc.frequency.linearRampToValueAtTime(120, ctx.currentTime + 0.25);

    gain.gain.setValueAtTime(0.25, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.3);

    const filter = ctx.createBiquadFilter();
    filter.type = 'lowpass';
    filter.frequency.setValueAtTime(800, ctx.currentTime);

    osc.connect(filter);
    filter.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.3);
  } catch (e) {
    console.warn('[NetVisor Sound] Web Audio playback failed', e);
  }
};

// Play a theme switch tone (soft frequency warp)
export const playWarpSound = () => {
  const enabled = isSoundEnabled();
  if (!enabled) return;
  try {
    const ctx = getAudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(220, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.25);

    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);

    const delay = ctx.createDelay();
    delay.delayTime.setValueAtTime(0.05, ctx.currentTime);

    osc.connect(delay);
    osc.connect(gain);
    delay.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.25);
  } catch (e) {
    console.warn('[NetVisor Sound] Web Audio playback failed', e);
  }
};
