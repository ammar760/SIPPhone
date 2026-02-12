/**
 * Phone UI Controller — Electron renderer
 * Uses window.sipPhone (IPC bridge from preload.js) to communicate
 * with the SIP UA running in the main process over raw UDP.
 * No WebSocket or browser SIP library needed.
 */
(function () {
  'use strict';

  const sip = window.sipPhone;

  // ---- Initialize Logger ----
  const logger = new SIPLogger('logsBody');

  // ---- Config management ----
  function loadConfig() {
    const saved = localStorage.getItem('sipPhoneConfig');
    if (saved) {
      try {
        const cfg = JSON.parse(saved);
        // Migrate: force TLS if old config had UDP/TCP (AWS PBX needs TLS)
        if (!cfg.transport || cfg.transport === 'udp' || cfg.transport === 'tcp') {
          cfg.transport = 'tls';
        }
        return cfg;
      } catch (e) {}
    }
    return {
      server: 'pbx.catalectconsulting.com',
      port: '5060',
      transport: 'tls',
      extension: '19544818620',
      password: '326976df3213d2ad06a16da6f607f926',
      displayName: 'SIP Phone',
    };
  }

  function saveConfig(cfg) {
    localStorage.setItem('sipPhoneConfig', JSON.stringify(cfg));
  }

  const config = loadConfig();

  // ---- Load config into form ----
  function loadConfigToForm() {
    document.getElementById('sipServer').value = config.server || '';
    document.getElementById('sipPort').value = config.port || '5060';
    document.getElementById('sipTransport').value = config.transport || 'tls';
    document.getElementById('sipExtension').value = config.extension || '';
    document.getElementById('sipPassword').value = config.password || '';
    document.getElementById('sipDisplayName').value = config.displayName || '';
    document.getElementById('accountDisplay').textContent = config.extension || '-';
  }
  loadConfigToForm();

  // ---- Audio Engine (renderer side) ----
  let audioContext = null;
  let micStream = null;
  let micProcessor = null;

  /**
   * Start microphone capture and send PCM to main process
   */
  async function startMicrophone() {
    try {
      audioContext = new AudioContext({ sampleRate: 8000 });

      micStream = await navigator.mediaDevices.getUserMedia({
        audio: {
          sampleRate: 8000,
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        }
      });

      const source = audioContext.createMediaStreamSource(micStream);

      // ScriptProcessor to get raw PCM samples
      micProcessor = audioContext.createScriptProcessor(1024, 1, 1);

      micProcessor.onaudioprocess = (e) => {
        const float32Data = e.inputBuffer.getChannelData(0);
        // Convert float32 [-1,1] to int16
        const int16Data = new Int16Array(float32Data.length);
        for (let i = 0; i < float32Data.length; i++) {
          let s = Math.max(-1, Math.min(1, float32Data[i]));
          int16Data[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
        }
        // Send to main process for RTP encoding and sending
        sip.sendMicAudio(int16Data.buffer);
      };

      source.connect(micProcessor);
      micProcessor.connect(audioContext.destination);

      logger.info('Microphone started (8kHz mono)');
    } catch (err) {
      logger.error(`Microphone error: ${err.message}`);
    }
  }

  function stopMicrophone() {
    if (micProcessor) { micProcessor.disconnect(); micProcessor = null; }
    if (micStream) { micStream.getTracks().forEach(t => t.stop()); micStream = null; }
    if (audioContext) { audioContext.close().catch(() => {}); audioContext = null; }
  }

  /**
   * Play received PCM audio from the remote party
   */
  function playRemoteAudio(arrayBuffer) {
    if (!audioContext) {
      audioContext = new AudioContext({ sampleRate: 8000 });
    }
    const int16Data = new Int16Array(arrayBuffer);
    const float32Data = new Float32Array(int16Data.length);
    for (let i = 0; i < int16Data.length; i++) {
      float32Data[i] = int16Data[i] / 32768.0;
    }

    const buffer = audioContext.createBuffer(1, float32Data.length, 8000);
    buffer.getChannelData(0).set(float32Data);

    const source = audioContext.createBufferSource();
    source.buffer = buffer;
    source.connect(audioContext.destination);
    source.start();
  }

  // ---- IPC Event Handlers from main process ----

  sip.onLog((type, message) => {
    logger.log(type, message);
  });

  sip.onStatus((state, text) => {
    setStatus(state, text);
  });

  let callTimer = null;
  let callSeconds = 0;

  sip.onCallState((state, info) => {
    if (state === 'calling') {
      showCallUI(info, 'Calling...');
    } else if (state === 'ringing') {
      updateCallStatus('Ringing...');
    } else if (state === 'ringing-in') {
      showCallUI(info, 'Incoming Call...');
      document.getElementById('btnAnswer').style.display = '';
      document.getElementById('btnHangup').style.display = '';
      document.getElementById('btnCall').style.display = 'none';
    } else if (state === 'active') {
      updateCallStatus('Connected');
      startCallTimer();
      document.getElementById('btnAnswer').style.display = 'none';
      document.getElementById('incallControls').style.display = '';
      startMicrophone();
    } else if (state === 'idle') {
      stopCallTimer();
      hideCallUI();
      stopMicrophone();
    }
  });

  sip.onRemoteAudio((arrayBuffer) => {
    playRemoteAudio(arrayBuffer);
  });

  // ---- UI Helpers ----

  function setStatus(state, text) {
    const dot = document.querySelector('.status-dot');
    const label = document.getElementById('statusText');
    const btnReg = document.getElementById('btnRegister');
    const btnUnreg = document.getElementById('btnUnregister');

    dot.className = 'status-dot';
    if (state === 'connected') dot.classList.add('connected');
    if (state === 'connecting') dot.classList.add('connecting');
    label.textContent = text;

    if (state === 'connected') {
      btnReg.style.display = 'none';
      btnUnreg.style.display = '';
    } else if (state === 'disconnected') {
      btnReg.style.display = '';
      btnUnreg.style.display = 'none';
    }
  }

  function showCallUI(remote, status) {
    document.getElementById('callInfo').style.display = '';
    document.getElementById('callRemote').textContent = remote;
    document.getElementById('callStatus').textContent = status;
    document.getElementById('callDuration').textContent = '00:00';
    document.getElementById('btnCall').style.display = 'none';
    document.getElementById('btnHangup').style.display = '';
  }

  function hideCallUI() {
    document.getElementById('callInfo').style.display = 'none';
    document.getElementById('incallControls').style.display = 'none';
    document.getElementById('btnCall').style.display = '';
    document.getElementById('btnHangup').style.display = 'none';
    document.getElementById('btnAnswer').style.display = 'none';
    document.getElementById('btnMute').classList.remove('active');
    document.getElementById('btnHold').classList.remove('active');
  }

  function updateCallStatus(status) {
    document.getElementById('callStatus').textContent = status;
  }

  function startCallTimer() {
    callSeconds = 0;
    updateDuration();
    callTimer = setInterval(() => { callSeconds++; updateDuration(); }, 1000);
  }

  function stopCallTimer() {
    if (callTimer) { clearInterval(callTimer); callTimer = null; }
  }

  function updateDuration() {
    const mins = Math.floor(callSeconds / 60).toString().padStart(2, '0');
    const secs = (callSeconds % 60).toString().padStart(2, '0');
    document.getElementById('callDuration').textContent = `${mins}:${secs}`;
  }

  // ---- Dialpad ----
  document.querySelectorAll('.dial-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const digit = btn.getAttribute('data-digit');
      document.getElementById('dialInput').value += digit;
      document.getElementById('dialInput').focus();
      playDTMFTone(digit);
      sip.sendDtmf(digit);
    });
  });

  document.getElementById('btnBackspace').addEventListener('click', () => {
    const input = document.getElementById('dialInput');
    input.value = input.value.slice(0, -1);
    input.focus();
  });

  // ---- Call / Hangup / Answer ----
  document.getElementById('btnCall').addEventListener('click', () => {
    const number = document.getElementById('dialInput').value.trim();
    if (number) sip.call(number);
  });

  document.getElementById('btnHangup').addEventListener('click', () => sip.hangup());
  document.getElementById('btnAnswer').addEventListener('click', () => sip.answer());

  document.getElementById('dialInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const number = e.target.value.trim();
      if (number) sip.call(number);
    }
  });

  // ---- In-call controls ----
  document.getElementById('btnMute').addEventListener('click', async () => {
    const result = await sip.toggleMute();
    const muted = result.muted;
    document.getElementById('btnMute').classList.toggle('active', muted);
    document.getElementById('btnMute').querySelector('i').className =
      muted ? 'fas fa-microphone-slash' : 'fas fa-microphone';
  });

  document.getElementById('btnHold').addEventListener('click', () => {
    logger.warn('Hold requires re-INVITE — not yet implemented');
  });

  document.getElementById('btnTransfer').addEventListener('click', () => {
    logger.warn('Transfer not yet implemented for direct SIP mode');
  });

  document.getElementById('btnDtmf').addEventListener('click', () => {
    document.getElementById('dialInput').focus();
    logger.info('Use dialpad to send DTMF tones during call');
  });

  // ---- Register / Unregister ----
  document.getElementById('btnRegister').addEventListener('click', () => sip.register(config));
  document.getElementById('btnUnregister').addEventListener('click', () => sip.unregister());

  // ---- Settings ----
  document.getElementById('btnSettings').addEventListener('click', () => {
    const panel = document.getElementById('settingsPanel');
    panel.style.display = panel.style.display === 'none' ? '' : 'none';
  });

  document.getElementById('btnSaveSettings').addEventListener('click', () => {
    config.server = document.getElementById('sipServer').value.trim();
    config.port = document.getElementById('sipPort').value.trim();
    config.transport = document.getElementById('sipTransport').value;
    config.extension = document.getElementById('sipExtension').value.trim();
    config.password = document.getElementById('sipPassword').value.trim();
    config.displayName = document.getElementById('sipDisplayName').value.trim();
    saveConfig(config);
    document.getElementById('accountDisplay').textContent = config.extension;
    document.getElementById('settingsPanel').style.display = 'none';
    logger.info('Configuration saved');
  });

  // ---- Log Filters ----
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      logger.setFilter(btn.getAttribute('data-filter'));
    });
  });

  document.getElementById('btnClearLogs').addEventListener('click', () => {
    logger.clear();
    logger.info('Logs cleared');
  });

  document.getElementById('btnExportLogs').addEventListener('click', () => {
    logger.export();
    logger.info('Logs exported');
  });

  // ---- DTMF Audio Feedback ----
  const dtmfAudioCtx = new (window.AudioContext || window.webkitAudioContext)();

  const dtmfFreqs = {
    '1': [697, 1209], '2': [697, 1336], '3': [697, 1477],
    '4': [770, 1209], '5': [770, 1336], '6': [770, 1477],
    '7': [852, 1209], '8': [852, 1336], '9': [852, 1477],
    '*': [941, 1209], '0': [941, 1336], '#': [941, 1477]
  };

  function playDTMFTone(digit) {
    const freqs = dtmfFreqs[digit];
    if (!freqs) return;
    const duration = 0.15;
    const osc1 = dtmfAudioCtx.createOscillator();
    const osc2 = dtmfAudioCtx.createOscillator();
    const gain = dtmfAudioCtx.createGain();
    osc1.frequency.value = freqs[0];
    osc2.frequency.value = freqs[1];
    gain.gain.value = 0.1;
    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(dtmfAudioCtx.destination);
    osc1.start();
    osc2.start();
    osc1.stop(dtmfAudioCtx.currentTime + duration);
    osc2.stop(dtmfAudioCtx.currentTime + duration);
  }

  // ---- Initial Log ----
  logger.info('SIP Phone v2 — Desktop (Electron)');
  logger.info(`Transport: ${config.transport.toUpperCase()} to ${config.server}:${config.port}`);
  logger.info(`Extension: ${config.extension}`);
  logger.info('No WebSocket needed — raw SIP over UDP/TCP');
  logger.info('Click "Connect" to register');

})();
