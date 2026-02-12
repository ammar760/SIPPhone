/**
 * JsSIP-based SIP Phone Engine
 * Uses JsSIP instead of SIP.js for broader compatibility with standard SIP servers
 */

class SIPPhoneEngine {
  constructor(logger) {
    this.logger = logger;
    this.ua = null;
    this.currentSession = null;
    this.registered = false;
    this.callTimer = null;
    this.callSeconds = 0;
    this.isMuted = false;
    this.isHeld = false;
    this.localStream = null;
    this.config = this._loadConfig();
  }

  _loadConfig() {
    const saved = localStorage.getItem('sipPhoneConfig');
    if (saved) {
      try { return JSON.parse(saved); } catch (e) { /* ignore */ }
    }
    return {
      server: 'pbx.catalectconsulting.com',
      port: '5060',
      wsUrl: 'wss://pbx.catalectconsulting.com:8089/ws',
      extension: '19544818620',
      password: '326976df3213d2ad06a16da6f607f926',
      displayName: 'SIP Phone'
    };
  }

  saveConfig(config) {
    this.config = config;
    localStorage.setItem('sipPhoneConfig', JSON.stringify(config));
    this.logger.info('Configuration saved');
  }

  getConfig() {
    return { ...this.config };
  }

  /**
   * Register with the SIP server via WebSocket
   */
  async register() {
    if (this.ua) {
      this.logger.warn('Already connected, disconnecting first...');
      this.unregister();
      await new Promise(r => setTimeout(r, 1000));
    }

    const { server, port, wsUrl, extension, password, displayName } = this.config;

    this.logger.info(`Connecting to ${server}:${port} as ${extension}...`);
    this.logger.sip(`WebSocket URL: ${wsUrl}`);
    this.logger.sip(`SIP URI: sip:${extension}@${server}`);

    this._setStatus('connecting', 'Connecting...');

    try {
      // Build JsSIP configuration
      const socket = new JsSIP.WebSocketInterface(wsUrl);

      const configuration = {
        sockets: [socket],
        uri: `sip:${extension}@${server}`,
        password: password,
        display_name: displayName,
        register: true,
        register_expires: 300,
        session_timers: false,
        user_agent: 'SIPPhone/1.0',
        no_answer_timeout: 60,
        connection_recovery_min_interval: 2,
        connection_recovery_max_interval: 30,
      };

      this.ua = new JsSIP.UA(configuration);

      // ---- UA Event Handlers ----
      this.ua.on('connecting', (e) => {
        this.logger.sip('WebSocket connecting...');
        this._setStatus('connecting', 'Connecting...');
      });

      this.ua.on('connected', (e) => {
        this.logger.sip('WebSocket connected');
        this._setStatus('connecting', 'WS Connected, registering...');
      });

      this.ua.on('disconnected', (e) => {
        this.logger.sip('WebSocket disconnected');
        this.registered = false;
        this._setStatus('disconnected', 'Disconnected');
      });

      this.ua.on('registered', (e) => {
        this.logger.sip(`Registered successfully (expires: ${e.response?.getHeader('Expires') || 'N/A'}s)`);
        this.registered = true;
        this._setStatus('connected', 'Registered');
      });

      this.ua.on('unregistered', (e) => {
        this.logger.sip('Unregistered');
        this.registered = false;
        this._setStatus('disconnected', 'Unregistered');
      });

      this.ua.on('registrationFailed', (e) => {
        const cause = e.cause || 'Unknown';
        this.logger.error(`Registration failed: ${cause}`);
        if (e.response) {
          this.logger.sip(`Response: ${e.response.status_code} ${e.response.reason_phrase}`);
        }
        this.registered = false;
        this._setStatus('disconnected', `Reg Failed: ${cause}`);
      });

      this.ua.on('registrationExpiring', () => {
        this.logger.sip('Registration expiring, re-registering...');
      });

      // Incoming call
      this.ua.on('newRTCSession', (data) => {
        const session = data.session;

        if (session.direction === 'incoming') {
          this.logger.call(`Incoming call from ${data.request.from.toString()}`);
          this._handleIncomingCall(session, data.request);
        }
      });

      this.ua.on('sipEvent', (e) => {
        this.logger.sip(`SIP Event: ${JSON.stringify(e)}`);
      });

      // Start the UA
      this.ua.start();
      this.logger.info('JsSIP UA started');

    } catch (err) {
      this.logger.error(`Connection error: ${err.message}`);
      this._setStatus('disconnected', 'Error');
    }
  }

  /**
   * Unregister and disconnect
   */
  unregister() {
    if (this.ua) {
      this.logger.info('Disconnecting...');
      try {
        this.ua.stop();
      } catch (e) {
        this.logger.warn(`Disconnect error: ${e.message}`);
      }
      this.ua = null;
      this.registered = false;
      this._setStatus('disconnected', 'Disconnected');
    }
  }

  /**
   * Make an outbound call
   */
  async call(target) {
    if (!this.registered) {
      this.logger.error('Not registered — cannot make call');
      return;
    }

    if (this.currentSession) {
      this.logger.warn('Already in a call');
      return;
    }

    if (!target || target.trim() === '') {
      this.logger.warn('No number entered');
      return;
    }

    const { server } = this.config;
    const sipTarget = target.includes('@') ? `sip:${target}` : `sip:${target}@${server}`;

    this.logger.call(`Calling ${target}...`);
    this.logger.sip(`Target URI: ${sipTarget}`);

    try {
      const callOptions = {
        mediaConstraints: { audio: true, video: false },
        pcConfig: {
          iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
          ]
        },
        rtcOfferConstraints: {
          offerToReceiveAudio: true,
          offerToReceiveVideo: false
        }
      };

      const session = this.ua.call(sipTarget, callOptions);
      this._setupSessionHandlers(session, target);
      this.currentSession = session;

      this._showCallUI(target, 'Calling...');

    } catch (err) {
      this.logger.error(`Call failed: ${err.message}`);
      this._hideCallUI();
    }
  }

  /**
   * Handle incoming call
   */
  _handleIncomingCall(session, request) {
    this.currentSession = session;
    const from = request.from.toString();

    this._setupSessionHandlers(session, from);

    // Show answer/reject UI
    document.getElementById('btnAnswer').style.display = '';
    document.getElementById('btnHangup').style.display = '';
    document.getElementById('btnCall').style.display = 'none';

    this._showCallUI(from, 'Incoming Call...');

    // Play ringtone
    try {
      document.getElementById('ringtone').play().catch(() => {});
    } catch (e) {}
  }

  /**
   * Answer an incoming call
   */
  answer() {
    if (!this.currentSession) {
      this.logger.warn('No incoming call to answer');
      return;
    }

    this.logger.call('Answering call...');

    try {
      document.getElementById('ringtone').pause();
      document.getElementById('ringtone').currentTime = 0;
    } catch (e) {}

    const answerOptions = {
      mediaConstraints: { audio: true, video: false },
      pcConfig: {
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' }
        ]
      }
    };

    this.currentSession.answer(answerOptions);
  }

  /**
   * Hang up current call
   */
  hangup() {
    if (!this.currentSession) {
      this.logger.warn('No active call');
      return;
    }

    this.logger.call('Hanging up...');

    try {
      document.getElementById('ringtone').pause();
      document.getElementById('ringtone').currentTime = 0;
    } catch (e) {}

    try {
      this.currentSession.terminate();
    } catch (e) {
      this.logger.warn(`Hangup error: ${e.message}`);
    }
  }

  /**
   * Toggle mute
   */
  toggleMute() {
    if (!this.currentSession) return;

    if (this.isMuted) {
      this.currentSession.unmute({ audio: true });
      this.isMuted = false;
      this.logger.call('Unmuted');
    } else {
      this.currentSession.mute({ audio: true });
      this.isMuted = true;
      this.logger.call('Muted');
    }

    return this.isMuted;
  }

  /**
   * Toggle hold
   */
  toggleHold() {
    if (!this.currentSession) return;

    if (this.isHeld) {
      this.currentSession.unhold();
      this.isHeld = false;
      this.logger.call('Call resumed');
    } else {
      this.currentSession.hold();
      this.isHeld = true;
      this.logger.call('Call on hold');
    }

    return this.isHeld;
  }

  /**
   * Send DTMF tone
   */
  sendDTMF(digit) {
    if (!this.currentSession) return;
    this.currentSession.sendDTMF(digit);
    this.logger.sip(`DTMF sent: ${digit}`);
  }

  /**
   * Blind transfer
   */
  transfer(target) {
    if (!this.currentSession) {
      this.logger.warn('No active call to transfer');
      return;
    }

    const { server } = this.config;
    const transferTarget = target.includes('@') ? `sip:${target}` : `sip:${target}@${server}`;

    this.logger.call(`Transferring to ${target}...`);
    try {
      this.currentSession.refer(transferTarget);
    } catch (e) {
      this.logger.error(`Transfer failed: ${e.message}`);
    }
  }

  // ---- Private helpers ----

  _setupSessionHandlers(session, remoteId) {
    session.on('progress', (e) => {
      this.logger.sip(`Call progress: ${e.originator} (${e.response?.status_code || ''})`);
      this._updateCallStatus('Ringing...');
    });

    session.on('accepted', (e) => {
      this.logger.call('Call accepted / connected');
      this._updateCallStatus('Connected');
      this._startCallTimer();

      document.getElementById('btnAnswer').style.display = 'none';
      document.getElementById('incallControls').style.display = '';
    });

    session.on('confirmed', () => {
      this.logger.sip('Call confirmed (ACK)');

      // Attach remote audio
      const remoteAudio = document.getElementById('remoteAudio');
      if (session.connection) {
        const receivers = session.connection.getReceivers();
        if (receivers.length > 0) {
          const remoteStream = new MediaStream();
          receivers.forEach(receiver => {
            remoteStream.addTrack(receiver.track);
          });
          remoteAudio.srcObject = remoteStream;
          remoteAudio.play().catch(e => this.logger.warn(`Audio play error: ${e.message}`));
          this.logger.debug('Remote audio attached');
        }
      }
    });

    session.on('ended', (e) => {
      const cause = e.cause || 'Normal';
      this.logger.call(`Call ended: ${cause}`);
      this._endCall();
    });

    session.on('failed', (e) => {
      const cause = e.cause || 'Unknown';
      this.logger.error(`Call failed: ${cause}`);
      if (e.message) {
        this.logger.sip(`Failure response: ${e.message.status_code || ''} ${e.message.reason_phrase || ''}`);
      }
      this._endCall();
    });

    session.on('hold', (e) => {
      this.logger.call(`Call put on hold by ${e.originator}`);
    });

    session.on('unhold', (e) => {
      this.logger.call(`Call resumed by ${e.originator}`);
    });

    session.on('muted', (e) => {
      this.logger.debug(`Muted: audio=${e.audio}`);
    });

    session.on('unmuted', (e) => {
      this.logger.debug(`Unmuted: audio=${e.audio}`);
    });

    session.on('newDTMF', (e) => {
      if (e.originator === 'remote') {
        this.logger.sip(`Remote DTMF: ${e.dtmf.tone}`);
      }
    });

    session.on('newInfo', (e) => {
      this.logger.sip(`SIP INFO from ${e.originator}`);
    });

    session.on('icecandidate', (e) => {
      this.logger.debug(`ICE candidate: ${e.candidate.candidate.substring(0, 60)}...`);
    });

    // Handle peerconnection for media
    session.on('peerconnection', (e) => {
      this.logger.debug('PeerConnection created');

      e.peerconnection.ontrack = (event) => {
        this.logger.debug('Remote track received');
        const remoteAudio = document.getElementById('remoteAudio');
        remoteAudio.srcObject = event.streams[0];
        remoteAudio.play().catch(err => this.logger.warn(`Audio play: ${err.message}`));
      };

      e.peerconnection.oniceconnectionstatechange = () => {
        const state = e.peerconnection.iceConnectionState;
        this.logger.debug(`ICE state: ${state}`);
      };
    });
  }

  _startCallTimer() {
    this.callSeconds = 0;
    this._updateDuration();
    this.callTimer = setInterval(() => {
      this.callSeconds++;
      this._updateDuration();
    }, 1000);
  }

  _stopCallTimer() {
    if (this.callTimer) {
      clearInterval(this.callTimer);
      this.callTimer = null;
    }
  }

  _updateDuration() {
    const mins = Math.floor(this.callSeconds / 60).toString().padStart(2, '0');
    const secs = (this.callSeconds % 60).toString().padStart(2, '0');
    const el = document.getElementById('callDuration');
    if (el) el.textContent = `${mins}:${secs}`;
  }

  _endCall() {
    this._stopCallTimer();
    this.currentSession = null;
    this.isMuted = false;
    this.isHeld = false;
    this._hideCallUI();

    try {
      document.getElementById('ringtone').pause();
      document.getElementById('ringtone').currentTime = 0;
    } catch (e) {}

    // Clean up local stream
    if (this.localStream) {
      this.localStream.getTracks().forEach(t => t.stop());
      this.localStream = null;
    }
  }

  _showCallUI(remote, status) {
    document.getElementById('callInfo').style.display = '';
    document.getElementById('callRemote').textContent = remote;
    document.getElementById('callStatus').textContent = status;
    document.getElementById('callDuration').textContent = '00:00';
    document.getElementById('btnCall').style.display = 'none';
    document.getElementById('btnHangup').style.display = '';
  }

  _hideCallUI() {
    document.getElementById('callInfo').style.display = 'none';
    document.getElementById('incallControls').style.display = 'none';
    document.getElementById('btnCall').style.display = '';
    document.getElementById('btnHangup').style.display = 'none';
    document.getElementById('btnAnswer').style.display = 'none';

    // Reset mute/hold buttons
    document.getElementById('btnMute').classList.remove('active');
    document.getElementById('btnHold').classList.remove('active');
  }

  _updateCallStatus(status) {
    const el = document.getElementById('callStatus');
    if (el) el.textContent = status;
  }

  _setStatus(state, text) {
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
}
