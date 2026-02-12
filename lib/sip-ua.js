/**
 * SIP User Agent — full SIP stack over UDP, TCP, or TLS
 * Handles REGISTER, INVITE, ACK, BYE, CANCEL, and digest authentication
 * Connects directly to SIP port (typically 5060/5061) — no WebSocket needed
 * 
 * Transport: UDP, TCP, or TLS (TLS recommended for AWS-hosted PBX)
 */

const dgram = require('dgram');
const net = require('net');
const tls = require('tls');
const dns = require('dns');
const crypto = require('crypto');
const os = require('os');
const EventEmitter = require('events');
const RtpEngine = require('./rtp-engine');

// ===== Helpers =====

function generateTag() {
  return crypto.randomBytes(8).toString('hex');
}

function generateBranch() {
  return 'z9hG4bK' + crypto.randomBytes(8).toString('hex');
}

function generateCallId() {
  return crypto.randomBytes(12).toString('hex');
}

/**
 * Get the local IP address that routes to a given remote host
 */
function getLocalIp(remoteHost) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    sock.connect(1, remoteHost, () => {
      const addr = sock.address();
      sock.close();
      resolve(addr.address);
    });
    sock.on('error', () => {
      sock.close();
      // Fallback: find first non-internal IPv4
      const ifaces = os.networkInterfaces();
      for (const name of Object.keys(ifaces)) {
        for (const iface of ifaces[name]) {
          if (iface.family === 'IPv4' && !iface.internal) {
            return resolve(iface.address);
          }
        }
      }
      resolve('127.0.0.1');
    });
  });
}

/**
 * Resolve hostname to IP for logging
 */
function resolveHostname(hostname) {
  return new Promise((resolve) => {
    // If already an IP, return as-is
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      resolve(hostname);
      return;
    }
    dns.lookup(hostname, { family: 4 }, (err, address) => {
      if (err) {
        resolve(null);
      } else {
        resolve(address);
      }
    });
  });
}

// ===== SIP Message Parser =====

function parseSipMessage(data) {
  const str = typeof data === 'string' ? data : data.toString('utf8');
  const headerEnd = str.indexOf('\r\n\r\n');
  const headerSection = str.substring(0, headerEnd);
  const body = headerEnd >= 0 ? str.substring(headerEnd + 4) : '';
  const lines = headerSection.split('\r\n');
  const firstLine = lines[0];

  const msg = { headers: {}, body };

  // Request or response?
  if (firstLine.startsWith('SIP/2.0')) {
    // Response: "SIP/2.0 200 OK"
    const parts = firstLine.match(/^SIP\/2\.0\s+(\d+)\s+(.*)$/);
    msg.type = 'response';
    msg.statusCode = parseInt(parts[1]);
    msg.reasonPhrase = parts[2];
  } else {
    // Request: "REGISTER sip:server SIP/2.0"
    const parts = firstLine.match(/^(\w+)\s+(.+)\s+SIP\/2\.0$/);
    msg.type = 'request';
    msg.method = parts[1];
    msg.uri = parts[2];
  }

  // Parse headers
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx < 0) continue;
    const name = lines[i].substring(0, colonIdx).trim().toLowerCase();
    const value = lines[i].substring(colonIdx + 1).trim();
    // Support multiple headers with same name
    if (msg.headers[name]) {
      if (Array.isArray(msg.headers[name])) {
        msg.headers[name].push(value);
      } else {
        msg.headers[name] = [msg.headers[name], value];
      }
    } else {
      msg.headers[name] = value;
    }
  }

  msg.raw = str;
  return msg;
}

/**
 * Parse SDP body into a structured object
 */
function parseSdp(sdpText) {
  const result = { media: [] };
  let currentMedia = null;

  for (const line of sdpText.split('\r\n')) {
    if (!line || line.length < 2 || line[1] !== '=') continue;
    const type = line[0];
    const value = line.substring(2);

    if (type === 'c' && value.startsWith('IN IP4')) {
      const ip = value.split(' ')[2];
      if (currentMedia) currentMedia.ip = ip;
      else result.connectionIp = ip;
    } else if (type === 'm') {
      const parts = value.split(' ');
      currentMedia = {
        type: parts[0],           // "audio"
        port: parseInt(parts[1]),
        proto: parts[2],          // "RTP/AVP"
        payloadTypes: parts.slice(3).map(Number),
        ip: result.connectionIp,   // inherit connection IP
        attributes: []
      };
      result.media.push(currentMedia);
    } else if (type === 'a' && currentMedia) {
      currentMedia.attributes.push(value);
      if (value.startsWith('rtpmap:')) {
        const match = value.match(/rtpmap:(\d+)\s+(\S+)/);
        if (match) {
          if (!currentMedia.rtpmap) currentMedia.rtpmap = {};
          currentMedia.rtpmap[parseInt(match[1])] = match[2];
        }
      }
    }
  }

  return result;
}

/**
 * Parse WWW-Authenticate header
 */
function parseAuthHeader(header) {
  const result = {};
  const match = header.match(/^(\w+)\s+(.*)$/);
  result.scheme = match[1]; // "Digest"
  const params = match[2];
  const re = /(\w+)=(?:"([^"]+)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(params))) {
    result[m[1]] = m[2] || m[3];
  }
  return result;
}

/**
 * Compute digest authentication response
 */
function computeDigestResponse(auth, method, uri, username, password) {
  const ha1 = crypto.createHash('md5').update(`${username}:${auth.realm}:${password}`).digest('hex');
  const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');
  const response = crypto.createHash('md5').update(`${ha1}:${auth.nonce}:${ha2}`).digest('hex');
  return response;
}

function buildAuthorizationHeader(auth, method, uri, username, password) {
  const response = computeDigestResponse(auth, method, uri, username, password);
  return `Digest username="${username}", realm="${auth.realm}", nonce="${auth.nonce}", uri="${uri}", response="${response}", algorithm=MD5`;
}

// ===== SIP UA =====

class SipUA extends EventEmitter {
  constructor(config) {
    super();
    this.config = {
      server: config.server || 'pbx.catalectconsulting.com',
      port: parseInt(config.port) || 5060,
      extension: config.extension || '19544818620',
      password: config.password || '',
      displayName: config.displayName || 'SIP Phone',
      transport: (config.transport || 'tls').toLowerCase(),  // default TLS since AWS PBX often requires it
    };

    // Auto-select port based on transport if using default
    if (this.config.transport === 'tls' && this.config.port === 5060) {
      this.config.port = 5061;
    }

    // UDP socket
    this.udpSocket = null;
    // TCP/TLS socket (TLS wraps TCP)
    this.tcpSocket = null;
    this.tcpBuffer = Buffer.alloc(0);
    this.tcpConnected = false;

    this.localIp = null;
    this.localPort = 0;
    this.registered = false;
    this.registerTimer = null;
    this.localTag = generateTag();
    this.registerCallId = generateCallId();
    this.registerCSeq = 0;

    // Register retry
    this.registerRetryTimer = null;
    this.registerRetryCount = 0;
    this.maxRegisterRetries = 3;
    this.registerTimeoutMs = 5000;

    // Current call state
    this.call = null; // { callId, fromTag, toTag, localSdp, remoteSdp, rtpEngine, state, cseq }
  }

  /** Transport string for Via header: "UDP", "TCP", or "TLS" */
  _viaTransport() {
    // TLS uses TCP as the transport layer in SIP Via headers
    return this.config.transport === 'tls' ? 'TLS' : this.config.transport.toUpperCase();
  }

  /** Transport string for Contact/URI params */
  _contactTransport() {
    return this.config.transport === 'tls' ? 'tls' : this.config.transport.toLowerCase();
  }

  /**
   * Start the SIP UA — bind socket (UDP or TCP)
   */
  async start() {
    // DNS resolution logging
    const resolvedIp = await resolveHostname(this.config.server);
    if (resolvedIp) {
      this.emit('log', 'info', `DNS: ${this.config.server} → ${resolvedIp}`);
    } else {
      this.emit('log', 'error', `DNS: Failed to resolve ${this.config.server}`);
    }

    this.localIp = await getLocalIp(this.config.server);
    this.emit('log', 'info', `Local IP: ${this.localIp}`);
    this.emit('log', 'info', `Transport: ${this._viaTransport()}`);

    if (this.config.transport === 'tls') {
      return this._startTls();
    } else if (this.config.transport === 'tcp') {
      return this._startTcp();
    } else {
      return this._startUdp();
    }
  }

  /**
   * Start UDP transport
   */
  _startUdp() {
    return new Promise((resolve, reject) => {
      this.udpSocket = dgram.createSocket('udp4');

      this.udpSocket.on('error', (err) => {
        this.emit('log', 'error', `SIP UDP socket error: ${err.message}`);
      });

      this.udpSocket.on('message', (msg, rinfo) => {
        this.emit('log', 'debug', `← UDP from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
        this._handleMessage(msg, rinfo);
      });

      this.udpSocket.bind(0, '0.0.0.0', () => {
        const addr = this.udpSocket.address();
        this.localPort = addr.port;
        this.emit('log', 'sip', `SIP UDP socket bound on ${this.localIp}:${this.localPort}`);
        resolve();
      });
    });
  }

  /**
   * Start TCP transport — connect to SIP server
   */
  _startTcp() {
    return new Promise((resolve, reject) => {
      this.tcpSocket = new net.Socket();
      this.tcpBuffer = Buffer.alloc(0);
      this.tcpConnected = false;

      const connectTimeout = setTimeout(() => {
        this.emit('log', 'error', `TCP connect timeout to ${this.config.server}:${this.config.port}`);
        this.tcpSocket.destroy();
        reject(new Error('TCP connect timeout'));
      }, 10000);

      this.tcpSocket.connect(this.config.port, this.config.server, () => {
        clearTimeout(connectTimeout);
        this.tcpConnected = true;
        const addr = this.tcpSocket.address();
        this.localPort = addr.port;
        this.localIp = addr.address;
        this.emit('log', 'sip', `SIP TCP connected to ${this.config.server}:${this.config.port}`);
        this.emit('log', 'sip', `Local TCP endpoint: ${this.localIp}:${this.localPort}`);
        resolve();
      });

      this.tcpSocket.on('data', (data) => {
        this.emit('log', 'debug', `← TCP data (${data.length} bytes)`);
        this._handleTcpData(data);
      });

      this.tcpSocket.on('error', (err) => {
        clearTimeout(connectTimeout);
        this.emit('log', 'error', `SIP TCP error: ${err.message}`);
        this.tcpConnected = false;
        if (!this.registered) {
          this.emit('status', 'disconnected', `TCP error: ${err.message}`);
        }
      });

      this.tcpSocket.on('close', (hadError) => {
        this.emit('log', 'warn', `SIP TCP connection closed${hadError ? ' (with error)' : ''}`);
        this.tcpConnected = false;
        this.registered = false;
        this.emit('status', 'disconnected', 'TCP closed');
      });
    });
  }

  /**
   * Start TLS transport — encrypted SIP connection (SIPS)
   */
  _startTls() {
    return new Promise((resolve, reject) => {
      this.tcpBuffer = Buffer.alloc(0);
      this.tcpConnected = false;

      const connectTimeout = setTimeout(() => {
        this.emit('log', 'error', `TLS connect timeout to ${this.config.server}:${this.config.port}`);
        if (this.tcpSocket) this.tcpSocket.destroy();
        reject(new Error('TLS connect timeout'));
      }, 10000);

      const tlsOptions = {
        host: this.config.server,
        port: this.config.port,
        rejectUnauthorized: false,  // Many PBX use self-signed certs
        servername: this.config.server,
      };

      this.emit('log', 'sip', `Connecting TLS to ${this.config.server}:${this.config.port}...`);

      this.tcpSocket = tls.connect(tlsOptions, () => {
        clearTimeout(connectTimeout);
        this.tcpConnected = true;
        const addr = this.tcpSocket.address();
        this.localPort = addr.port;
        this.localIp = addr.address;
        const cipher = this.tcpSocket.getCipher();
        this.emit('log', 'sip', `SIP TLS connected to ${this.config.server}:${this.config.port}`);
        this.emit('log', 'info', `TLS cipher: ${cipher ? cipher.name : 'unknown'}`);
        this.emit('log', 'sip', `Local TLS endpoint: ${this.localIp}:${this.localPort}`);
        resolve();
      });

      this.tcpSocket.on('data', (data) => {
        this.emit('log', 'debug', `← TLS data (${data.length} bytes)`);
        this._handleTcpData(data);
      });

      this.tcpSocket.on('error', (err) => {
        clearTimeout(connectTimeout);
        this.emit('log', 'error', `SIP TLS error: ${err.message}`);
        this.tcpConnected = false;
        if (!this.registered) {
          this.emit('status', 'disconnected', `TLS error: ${err.message}`);
        }
      });

      this.tcpSocket.on('close', (hadError) => {
        this.emit('log', 'warn', `SIP TLS connection closed${hadError ? ' (with error)' : ''}`);
        this.tcpConnected = false;
        this.registered = false;
        this.emit('status', 'disconnected', 'TLS closed');
      });
    });
  }

  /**
   * Handle incoming TCP data — SIP over TCP message framing
   * SIP messages are delimited by Content-Length header
   */
  _handleTcpData(data) {
    this.tcpBuffer = Buffer.concat([this.tcpBuffer, data]);

    while (this.tcpBuffer.length > 0) {
      const str = this.tcpBuffer.toString('utf8');

      // Find end of headers
      const headerEnd = str.indexOf('\r\n\r\n');
      if (headerEnd < 0) {
        // Not enough data yet — wait for more
        break;
      }

      // Extract Content-Length from headers
      const headerSection = str.substring(0, headerEnd);
      const clMatch = headerSection.match(/Content-Length:\s*(\d+)/i);
      const contentLength = clMatch ? parseInt(clMatch[1]) : 0;

      // Total message length = headers + \r\n\r\n + body
      const totalLength = headerEnd + 4 + contentLength;
      const totalBytes = Buffer.byteLength(str.substring(0, totalLength), 'utf8');

      if (this.tcpBuffer.length < totalBytes) {
        // Not enough data for full message — wait for more
        break;
      }

      // Extract complete message
      const msgBuf = this.tcpBuffer.slice(0, totalBytes);
      this.tcpBuffer = this.tcpBuffer.slice(totalBytes);

      // Handle it as a SIP message
      const rinfo = { address: this.config.server, port: this.config.port };
      this._handleMessage(msgBuf, rinfo);
    }
  }

  /**
   * Stop the SIP UA
   */
  stop() {
    if (this.registerTimer) {
      clearInterval(this.registerTimer);
      this.registerTimer = null;
    }
    if (this.registerRetryTimer) {
      clearTimeout(this.registerRetryTimer);
      this.registerRetryTimer = null;
    }
    if (this.call) {
      this.hangup();
    }
    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch (e) {}
      this.udpSocket = null;
    }
    if (this.tcpSocket) {
      try { this.tcpSocket.destroy(); } catch (e) {}
      this.tcpSocket = null;
      this.tcpConnected = false;
    }
    this.registered = false;
    this.emit('status', 'disconnected', 'Stopped');
  }

  /**
   * Register with the SIP server
   */
  async register() {
    await this.start();

    this.emit('log', 'sip', `Sending REGISTER to ${this.config.server}:${this.config.port} via ${this._viaTransport()}`);
    this.emit('status', 'connecting', 'Registering...');

    this.registerCSeq++;
    this.registerRetryCount = 0;
    const request = this._buildRegister();
    this._send(request);

    // Start retry timer
    this._startRegisterRetryTimer();
  }

  /**
   * Start a retry timer for REGISTER — if no response in N seconds, resend
   */
  _startRegisterRetryTimer() {
    if (this.registerRetryTimer) {
      clearTimeout(this.registerRetryTimer);
    }

    this.registerRetryTimer = setTimeout(() => {
      if (this.registered) return; // Already registered

      this.registerRetryCount++;
      if (this.registerRetryCount > this.maxRegisterRetries) {
        this.emit('log', 'error', `REGISTER failed after ${this.maxRegisterRetries} retries — no response from server`);
        this.emit('status', 'disconnected', 'No response from server');
        return;
      }

      this.emit('log', 'warn', `No REGISTER response — retry ${this.registerRetryCount}/${this.maxRegisterRetries}`);
      this.registerCSeq++;
      const request = this._buildRegister();
      this._send(request);
      this._startRegisterRetryTimer(); // Schedule next retry
    }, this.registerTimeoutMs);
  }

  /**
   * Unregister
   */
  unregister() {
    if (!this.udpSocket && !this.tcpSocket) return;

    this.emit('log', 'sip', 'Sending REGISTER (Expires: 0) to unregister');
    this.registerCSeq++;
    const request = this._buildRegister(0);
    this._send(request);

    if (this.registerTimer) {
      clearInterval(this.registerTimer);
      this.registerTimer = null;
    }

    setTimeout(() => this.stop(), 2000);
  }

  /**
   * Make an outbound call
   */
  async invite(target) {
    if (!this.registered) {
      this.emit('log', 'error', 'Not registered — cannot make call');
      return;
    }
    if (this.call) {
      this.emit('log', 'warn', 'Already in a call');
      return;
    }

    const targetUri = target.includes('@')
      ? `sip:${target}`
      : `sip:${target}@${this.config.server}`;

    // Set up RTP (always UDP for media)
    const rtp = new RtpEngine();
    rtp.on('log', (msg) => this.emit('log', 'debug', msg));
    rtp.on('error', (err) => this.emit('log', 'error', `RTP error: ${err.message}`));
    rtp.on('audio', (pcmData) => this.emit('remoteAudio', pcmData));

    const rtpPort = await rtp.bind();

    const callId = generateCallId();
    const fromTag = generateTag();

    this.call = {
      callId,
      fromTag,
      toTag: null,
      targetUri,
      target,
      rtpEngine: rtp,
      rtpPort,
      state: 'calling',
      cseq: 1,
      branch: generateBranch(),
    };

    const sdp = this._buildSdp(rtpPort);
    this.call.localSdp = sdp;

    const invite = this._buildInvite(targetUri, callId, fromTag, sdp);
    this.emit('log', 'call', `Calling ${target}...`);
    this.emit('log', 'sip', `INVITE ${targetUri}`);
    this.emit('callState', 'calling', target);

    this._send(invite);
  }

  /**
   * Answer an incoming call
   */
  async answerIncoming() {
    if (!this.call || this.call.state !== 'ringing-in') {
      this.emit('log', 'warn', 'No incoming call to answer');
      return;
    }

    // Set up RTP
    const rtp = new RtpEngine();
    rtp.on('log', (msg) => this.emit('log', 'debug', msg));
    rtp.on('error', (err) => this.emit('log', 'error', `RTP error: ${err.message}`));
    rtp.on('audio', (pcmData) => this.emit('remoteAudio', pcmData));

    const rtpPort = await rtp.bind();
    this.call.rtpEngine = rtp;
    this.call.rtpPort = rtpPort;

    const sdp = this._buildSdp(rtpPort);
    this.call.localSdp = sdp;

    // Parse remote SDP to get RTP target
    if (this.call.remoteSdp) {
      const parsed = parseSdp(this.call.remoteSdp);
      if (parsed.media.length > 0) {
        const audio = parsed.media[0];
        const remoteIp = audio.ip || parsed.connectionIp;
        const remotePort = audio.port;
        const pt = audio.payloadTypes[0] || 0;
        rtp.start(remoteIp, remotePort, pt);
        this.emit('log', 'sip', `RTP -> ${remoteIp}:${remotePort} PT=${pt}`);
      }
    }

    // Send 200 OK
    const response = this._build200ForInvite(sdp);
    this._send(response);

    this.call.state = 'active';
    this.emit('log', 'call', 'Call answered');
    this.emit('callState', 'active', this.call.target);
  }

  /**
   * Hang up current call
   */
  hangup() {
    if (!this.call) {
      this.emit('log', 'warn', 'No active call');
      return;
    }

    if (this.call.state === 'calling') {
      // Send CANCEL
      const cancel = this._buildCancel();
      this._send(cancel);
      this.emit('log', 'sip', 'Sent CANCEL');
    } else if (this.call.state === 'ringing-in') {
      // Reject incoming - send 486 Busy
      const reject = this._build486();
      this._send(reject);
      this.emit('log', 'sip', 'Sent 486 Busy Here');
    } else {
      // Send BYE
      this.call.cseq++;
      const bye = this._buildBye();
      this._send(bye);
      this.emit('log', 'sip', 'Sent BYE');
    }

    this._endCall('User hangup');
  }

  /**
   * Toggle mute
   */
  toggleMute() {
    if (!this.call || !this.call.rtpEngine) return false;
    const muted = !this.call.rtpEngine.muted;
    this.call.rtpEngine.setMuted(muted);
    this.emit('log', 'call', muted ? 'Muted' : 'Unmuted');
    return muted;
  }

  /**
   * Send DTMF via SIP INFO (RFC 2976)
   */
  sendDtmf(digit) {
    if (!this.call || this.call.state !== 'active') return;

    this.call.cseq++;
    const info = this._buildInfo(digit);
    this._send(info);
    this.emit('log', 'sip', `DTMF INFO sent: ${digit}`);
  }

  /**
   * Feed microphone PCM data to the RTP engine
   */
  feedMicAudio(pcmData) {
    if (this.call && this.call.rtpEngine) {
      this.call.rtpEngine.feedMicAudio(pcmData);
    }
  }

  // ===================================================================
  //  SIP Message Builders
  // ===================================================================

  _buildRegister(expires = 300) {
    const { server, port, extension, displayName } = this.config;
    const branch = generateBranch();

    let msg = `REGISTER sip:${server} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.localTag}\r\n`;
    msg += `To: <sip:${extension}@${server}>\r\n`;
    msg += `Call-ID: ${this.registerCallId}\r\n`;
    msg += `CSeq: ${this.registerCSeq} REGISTER\r\n`;
    msg += `Contact: <sip:${extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    msg += `Expires: ${expires}\r\n`;
    msg += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildRegisterWithAuth(authHeader, expires = 300) {
    const { server, port, extension, password, displayName } = this.config;
    const branch = generateBranch();
    this.registerCSeq++;

    const auth = parseAuthHeader(authHeader);
    const uri = `sip:${server}`;
    const authResponse = buildAuthorizationHeader(auth, 'REGISTER', uri, extension, password);

    let msg = `REGISTER sip:${server} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.localTag}\r\n`;
    msg += `To: <sip:${extension}@${server}>\r\n`;
    msg += `Call-ID: ${this.registerCallId}\r\n`;
    msg += `CSeq: ${this.registerCSeq} REGISTER\r\n`;
    msg += `Contact: <sip:${extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    msg += `Expires: ${expires}\r\n`;
    msg += `Authorization: ${authResponse}\r\n`;
    msg += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildInvite(targetUri, callId, fromTag, sdp) {
    const { server, extension, displayName } = this.config;
    const branch = this.call.branch;

    let msg = `INVITE ${targetUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${fromTag}\r\n`;
    msg += `To: <${targetUri}>\r\n`;
    msg += `Call-ID: ${callId}\r\n`;
    msg += `CSeq: ${this.call.cseq} INVITE\r\n`;
    msg += `Contact: <sip:${extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    msg += `Content-Type: application/sdp\r\n`;
    msg += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: ${Buffer.byteLength(sdp)}\r\n`;
    msg += `\r\n`;
    msg += sdp;

    return msg;
  }

  _buildInviteWithAuth(authHeader) {
    const { server, extension, password, displayName } = this.config;
    this.call.cseq++;
    this.call.branch = generateBranch();
    const branch = this.call.branch;

    const auth = parseAuthHeader(authHeader);
    const authResponse = buildAuthorizationHeader(auth, 'INVITE', this.call.targetUri, extension, password);
    const sdp = this.call.localSdp;

    let msg = `INVITE ${this.call.targetUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.call.fromTag}\r\n`;
    msg += `To: <${this.call.targetUri}>\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.cseq} INVITE\r\n`;
    msg += `Contact: <sip:${extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    msg += `Authorization: ${authResponse}\r\n`;
    msg += `Content-Type: application/sdp\r\n`;
    msg += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: ${Buffer.byteLength(sdp)}\r\n`;
    msg += `\r\n`;
    msg += sdp;

    return msg;
  }

  _buildAck(toTag) {
    const { server, extension, displayName } = this.config;
    const branch = generateBranch();

    let msg = `ACK ${this.call.targetUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.call.fromTag}\r\n`;
    msg += `To: <${this.call.targetUri}>;tag=${toTag}\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.cseq} ACK\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildBye() {
    const { server, extension, displayName } = this.config;
    const branch = generateBranch();

    let toUri = this.call.targetUri;
    let toTag = this.call.toTag ? `;tag=${this.call.toTag}` : '';

    let msg = `BYE ${toUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.call.fromTag}\r\n`;
    msg += `To: <${toUri}>${toTag}\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.cseq} BYE\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildCancel() {
    const { server, extension, displayName } = this.config;

    let msg = `CANCEL ${this.call.targetUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${this.call.branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.call.fromTag}\r\n`;
    msg += `To: <${this.call.targetUri}>\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: 1 CANCEL\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildInfo(digit) {
    const { server, extension, displayName } = this.config;
    const branch = generateBranch();
    const body = `Signal=${digit}\r\nDuration=160\r\n`;
    let toTag = this.call.toTag ? `;tag=${this.call.toTag}` : '';

    let msg = `INFO ${this.call.targetUri} SIP/2.0\r\n`;
    msg += `Via: SIP/2.0/${this._viaTransport()} ${this.localIp}:${this.localPort};branch=${branch};rport\r\n`;
    msg += `Max-Forwards: 70\r\n`;
    msg += `From: "${displayName}" <sip:${extension}@${server}>;tag=${this.call.fromTag}\r\n`;
    msg += `To: <${this.call.targetUri}>${toTag}\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.cseq} INFO\r\n`;
    msg += `Content-Type: application/dtmf-relay\r\n`;
    msg += `Content-Length: ${Buffer.byteLength(body)}\r\n`;
    msg += `\r\n`;
    msg += body;

    return msg;
  }

  _build200ForInvite(sdp) {
    const { server, extension, displayName } = this.config;

    let msg = `SIP/2.0 200 OK\r\n`;
    msg += `Via: ${this.call.incomingVia}\r\n`;
    msg += `From: ${this.call.incomingFrom}\r\n`;
    msg += `To: ${this.call.incomingTo};tag=${this.call.localTag}\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.incomingCSeq} INVITE\r\n`;
    msg += `Contact: <sip:${extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    msg += `Content-Type: application/sdp\r\n`;
    msg += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    msg += `User-Agent: SIPPhone/2.0\r\n`;
    msg += `Content-Length: ${Buffer.byteLength(sdp)}\r\n`;
    msg += `\r\n`;
    msg += sdp;

    return msg;
  }

  _build486() {
    let msg = `SIP/2.0 486 Busy Here\r\n`;
    msg += `Via: ${this.call.incomingVia}\r\n`;
    msg += `From: ${this.call.incomingFrom}\r\n`;
    msg += `To: ${this.call.incomingTo};tag=${this.call.localTag || generateTag()}\r\n`;
    msg += `Call-ID: ${this.call.callId}\r\n`;
    msg += `CSeq: ${this.call.incomingCSeq} INVITE\r\n`;
    msg += `Content-Length: 0\r\n`;
    msg += `\r\n`;

    return msg;
  }

  _buildSdp(rtpPort) {
    const sessionId = Math.floor(Date.now() / 1000);

    let sdp = `v=0\r\n`;
    sdp += `o=SIPPhone ${sessionId} ${sessionId} IN IP4 ${this.localIp}\r\n`;
    sdp += `s=SIPPhone Call\r\n`;
    sdp += `c=IN IP4 ${this.localIp}\r\n`;
    sdp += `t=0 0\r\n`;
    sdp += `m=audio ${rtpPort} RTP/AVP 0 8 101\r\n`;
    sdp += `a=rtpmap:0 PCMU/8000\r\n`;
    sdp += `a=rtpmap:8 PCMA/8000\r\n`;
    sdp += `a=rtpmap:101 telephone-event/8000\r\n`;
    sdp += `a=fmtp:101 0-16\r\n`;
    sdp += `a=ptime:20\r\n`;
    sdp += `a=sendrecv\r\n`;

    return sdp;
  }

  // ===================================================================
  //  Message Handling
  // ===================================================================

  _handleMessage(data, rinfo) {
    let msg;
    try {
      msg = parseSipMessage(data);
    } catch (e) {
      this.emit('log', 'error', `Failed to parse SIP message: ${e.message}`);
      this.emit('log', 'debug', `Raw data: ${data.toString('utf8').substring(0, 200)}`);
      return;
    }

    // Log raw incoming message (first line + key headers)
    const firstLine = msg.raw.split('\r\n')[0];
    this.emit('log', 'debug', `← RAW: ${firstLine}`);

    if (msg.type === 'response') {
      this._handleResponse(msg);
    } else if (msg.type === 'request') {
      this._handleRequest(msg, rinfo);
    }
  }

  _handleResponse(msg) {
    const cseqHeader = msg.headers['cseq'] || '';
    const method = cseqHeader.split(' ')[1] || '';

    this.emit('log', 'sip', `← ${msg.statusCode} ${msg.reasonPhrase} (${method})`);

    if (method === 'REGISTER') {
      this._handleRegisterResponse(msg);
    } else if (method === 'INVITE') {
      this._handleInviteResponse(msg);
    } else if (method === 'BYE') {
      this.emit('log', 'sip', 'BYE acknowledged');
    } else if (method === 'CANCEL') {
      this.emit('log', 'sip', 'CANCEL acknowledged');
    }
  }

  _handleRegisterResponse(msg) {
    // Clear retry timer on any response
    if (this.registerRetryTimer) {
      clearTimeout(this.registerRetryTimer);
      this.registerRetryTimer = null;
    }

    if (msg.statusCode === 401 || msg.statusCode === 407) {
      // Authentication required
      const authHeader = msg.headers['www-authenticate'] || msg.headers['proxy-authenticate'];
      if (!authHeader) {
        this.emit('log', 'error', 'Auth required but no WWW-Authenticate header');
        this.emit('log', 'debug', `Response headers: ${JSON.stringify(msg.headers)}`);
        return;
      }
      this.emit('log', 'sip', 'Got 401 — sending credentials...');
      const authedRegister = this._buildRegisterWithAuth(authHeader);
      this._send(authedRegister);

      // Restart retry timer for the authenticated REGISTER
      this._startRegisterRetryTimer();
    } else if (msg.statusCode === 200) {
      this.registered = true;
      this.registerRetryCount = 0;
      this.emit('log', 'call', 'Registered successfully!');
      this.emit('status', 'connected', 'Registered');

      // Set up re-registration timer (every 250s for 300s expiry)
      if (this.registerTimer) clearInterval(this.registerTimer);
      this.registerTimer = setInterval(() => {
        this.emit('log', 'sip', 'Re-registering...');
        this.registerCSeq++;
        // Re-register with auth (send plain first to get new nonce)
        const request = this._buildRegister();
        this._send(request);
      }, 250 * 1000);
    } else {
      this.emit('log', 'error', `Registration failed: ${msg.statusCode} ${msg.reasonPhrase}`);
      this.emit('status', 'disconnected', `Reg failed: ${msg.statusCode}`);
    }
  }

  _handleInviteResponse(msg) {
    if (!this.call) return;

    // Extract To tag
    const toHeader = msg.headers['to'] || '';
    const toTagMatch = toHeader.match(/;tag=([^\s;]+)/);
    if (toTagMatch) this.call.toTag = toTagMatch[1];

    if (msg.statusCode === 100) {
      this.emit('log', 'sip', 'Trying...');
    } else if (msg.statusCode === 180 || msg.statusCode === 183) {
      this.call.state = 'ringing';
      this.emit('log', 'call', 'Ringing...');
      this.emit('callState', 'ringing', this.call.target);
    } else if (msg.statusCode === 401 || msg.statusCode === 407) {
      // Auth needed for INVITE
      const authHeader = msg.headers['www-authenticate'] || msg.headers['proxy-authenticate'];
      if (authHeader) {
        this.emit('log', 'sip', 'INVITE auth required — resending with credentials...');
        // Send ACK for the 401
        const ack = this._buildAck(this.call.toTag || '');
        this._send(ack);

        // Resend INVITE with auth
        const authedInvite = this._buildInviteWithAuth(authHeader);
        this._send(authedInvite);
      }
    } else if (msg.statusCode === 200) {
      // Call connected!
      this.call.state = 'active';
      this.call.remoteSdp = msg.body;
      this.emit('log', 'call', 'Call connected!');
      this.emit('callState', 'active', this.call.target);

      // Send ACK
      const ack = this._buildAck(this.call.toTag);
      this._send(ack);
      this.emit('log', 'sip', 'Sent ACK');

      // Start RTP
      if (msg.body) {
        const sdp = parseSdp(msg.body);
        if (sdp.media.length > 0) {
          const audio = sdp.media[0];
          const remoteIp = audio.ip || sdp.connectionIp;
          const remotePort = audio.port;
          const pt = audio.payloadTypes[0] || 0;
          this.call.rtpEngine.start(remoteIp, remotePort, pt);
          this.emit('log', 'sip', `RTP streaming to ${remoteIp}:${remotePort} (PT=${pt})`);
        }
      }
    } else if (msg.statusCode >= 400) {
      this.emit('log', 'error', `Call failed: ${msg.statusCode} ${msg.reasonPhrase}`);
      // Send ACK for error responses
      const ack = this._buildAck(this.call.toTag || '');
      this._send(ack);
      this._endCall(`${msg.statusCode} ${msg.reasonPhrase}`);
    }
  }

  _handleRequest(msg, rinfo) {
    this.emit('log', 'sip', `← ${msg.method} from ${rinfo.address}:${rinfo.port}`);

    if (msg.method === 'INVITE') {
      this._handleIncomingInvite(msg, rinfo);
    } else if (msg.method === 'ACK') {
      this.emit('log', 'sip', 'ACK received');
    } else if (msg.method === 'BYE') {
      this._handleBye(msg, rinfo);
    } else if (msg.method === 'CANCEL') {
      this._handleIncomingCancel(msg, rinfo);
    } else if (msg.method === 'OPTIONS') {
      // Reply 200 OK to OPTIONS (keepalive)
      this._replyToOptions(msg, rinfo);
    } else if (msg.method === 'NOTIFY') {
      // Reply 200 OK
      this._reply200(msg, rinfo);
    }
  }

  _handleIncomingInvite(msg, rinfo) {
    const fromHeader = msg.headers['from'] || '';
    const fromMatch = fromHeader.match(/<sip:([^@>]+)/);
    const callerId = fromMatch ? fromMatch[1] : 'Unknown';
    const callId = msg.headers['call-id'];
    const cseq = msg.headers['cseq'];
    const cseqNum = parseInt(cseq);

    // Store incoming call state
    if (this.call && this.call.state === 'active') {
      // Already in a call — send 486 Busy Here
      this.emit('log', 'call', `Rejecting incoming call from ${callerId} — busy`);
      let busy = `SIP/2.0 486 Busy Here\r\n`;
      busy += `Via: ${msg.headers['via']}\r\n`;
      busy += `From: ${fromHeader}\r\n`;
      busy += `To: ${msg.headers['to']};tag=${generateTag()}\r\n`;
      busy += `Call-ID: ${callId}\r\n`;
      busy += `CSeq: ${cseq}\r\n`;
      busy += `Content-Length: 0\r\n\r\n`;
      this._send(busy);
      return;
    }

    // Send 100 Trying
    let trying = `SIP/2.0 100 Trying\r\n`;
    trying += `Via: ${msg.headers['via']}\r\n`;
    trying += `From: ${fromHeader}\r\n`;
    trying += `To: ${msg.headers['to']}\r\n`;
    trying += `Call-ID: ${callId}\r\n`;
    trying += `CSeq: ${cseq}\r\n`;
    trying += `Content-Length: 0\r\n\r\n`;
    this._send(trying);

    // Send 180 Ringing
    const localTag = generateTag();
    let ringing = `SIP/2.0 180 Ringing\r\n`;
    ringing += `Via: ${msg.headers['via']}\r\n`;
    ringing += `From: ${fromHeader}\r\n`;
    ringing += `To: ${msg.headers['to']};tag=${localTag}\r\n`;
    ringing += `Call-ID: ${callId}\r\n`;
    ringing += `CSeq: ${cseq}\r\n`;
    ringing += `Contact: <sip:${this.config.extension}@${this.localIp}:${this.localPort};transport=${this._contactTransport()}>\r\n`;
    ringing += `Content-Length: 0\r\n\r\n`;
    this._send(ringing);

    this.call = {
      callId,
      fromTag: null, // remote's from tag
      toTag: null,
      localTag,
      target: callerId,
      rtpEngine: null,
      rtpPort: 0,
      state: 'ringing-in',
      cseq: 1,
      remoteSdp: msg.body,
      // Store headers needed for building responses
      incomingVia: msg.headers['via'],
      incomingFrom: fromHeader,
      incomingTo: msg.headers['to'],
      incomingCSeq: cseqNum,
      sourceAddress: rinfo.address,
      sourcePort: rinfo.port,
    };

    this.emit('log', 'call', `Incoming call from ${callerId}`);
    this.emit('callState', 'ringing-in', callerId);
  }

  _handleBye(msg, rinfo) {
    const callId = msg.headers['call-id'];

    // Send 200 OK for BYE
    let ok = `SIP/2.0 200 OK\r\n`;
    ok += `Via: ${msg.headers['via']}\r\n`;
    ok += `From: ${msg.headers['from']}\r\n`;
    ok += `To: ${msg.headers['to']}\r\n`;
    ok += `Call-ID: ${callId}\r\n`;
    ok += `CSeq: ${msg.headers['cseq']}\r\n`;
    ok += `Content-Length: 0\r\n\r\n`;
    this._send(ok);

    this.emit('log', 'sip', 'Received BYE — call ended by remote');
    this._endCall('Remote hangup');
  }

  _handleIncomingCancel(msg, rinfo) {
    // Reply 200 OK to CANCEL
    let ok = `SIP/2.0 200 OK\r\n`;
    ok += `Via: ${msg.headers['via']}\r\n`;
    ok += `From: ${msg.headers['from']}\r\n`;
    ok += `To: ${msg.headers['to']}\r\n`;
    ok += `Call-ID: ${msg.headers['call-id']}\r\n`;
    ok += `CSeq: ${msg.headers['cseq']}\r\n`;
    ok += `Content-Length: 0\r\n\r\n`;
    this._send(ok);

    // Also send 487 Request Terminated for the INVITE
    if (this.call && this.call.state === 'ringing-in') {
      let terminated = `SIP/2.0 487 Request Terminated\r\n`;
      terminated += `Via: ${this.call.incomingVia}\r\n`;
      terminated += `From: ${this.call.incomingFrom}\r\n`;
      terminated += `To: ${this.call.incomingTo};tag=${this.call.localTag}\r\n`;
      terminated += `Call-ID: ${this.call.callId}\r\n`;
      terminated += `CSeq: ${this.call.incomingCSeq} INVITE\r\n`;
      terminated += `Content-Length: 0\r\n\r\n`;
      this._send(terminated);
    }

    this.emit('log', 'call', 'Call cancelled by remote');
    this._endCall('Cancelled');
  }

  _replyToOptions(msg, rinfo) {
    let ok = `SIP/2.0 200 OK\r\n`;
    ok += `Via: ${msg.headers['via']}\r\n`;
    ok += `From: ${msg.headers['from']}\r\n`;
    ok += `To: ${msg.headers['to']};tag=${generateTag()}\r\n`;
    ok += `Call-ID: ${msg.headers['call-id']}\r\n`;
    ok += `CSeq: ${msg.headers['cseq']}\r\n`;
    ok += `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY, REFER\r\n`;
    ok += `Accept: application/sdp\r\n`;
    ok += `User-Agent: SIPPhone/2.0\r\n`;
    ok += `Content-Length: 0\r\n\r\n`;
    this._send(ok);
  }

  _reply200(msg, rinfo) {
    let ok = `SIP/2.0 200 OK\r\n`;
    ok += `Via: ${msg.headers['via']}\r\n`;
    ok += `From: ${msg.headers['from']}\r\n`;
    ok += `To: ${msg.headers['to']}\r\n`;
    ok += `Call-ID: ${msg.headers['call-id']}\r\n`;
    ok += `CSeq: ${msg.headers['cseq']}\r\n`;
    ok += `Content-Length: 0\r\n\r\n`;
    this._send(ok);
  }

  // ===================================================================
  //  Utilities
  // ===================================================================

  _send(message) {
    const firstLine = message.split('\r\n')[0];
    this.emit('log', 'debug', `→ SEND: ${firstLine}`);

    if (this.config.transport === 'tcp' || this.config.transport === 'tls') {
      this._sendTcp(message);
    } else {
      this._sendUdp(message);
    }
  }

  _sendUdp(message) {
    if (!this.udpSocket) {
      this.emit('log', 'error', 'UDP socket not available');
      return;
    }
    const buf = Buffer.from(message, 'utf8');
    this.udpSocket.send(buf, 0, buf.length, this.config.port, this.config.server, (err) => {
      if (err) {
        this.emit('log', 'error', `UDP send error: ${err.message}`);
      }
    });
  }

  _sendTcp(message) {
    if (!this.tcpSocket || !this.tcpConnected) {
      this.emit('log', 'error', 'TCP socket not connected');
      return;
    }
    try {
      this.tcpSocket.write(message, 'utf8', (err) => {
        if (err) {
          this.emit('log', 'error', `TCP write error: ${err.message}`);
        }
      });
    } catch (e) {
      this.emit('log', 'error', `TCP send exception: ${e.message}`);
    }
  }

  _endCall(reason) {
    if (!this.call) return;

    if (this.call.rtpEngine) {
      this.call.rtpEngine.close();
    }

    this.call = null;
    this.emit('log', 'call', `Call ended: ${reason}`);
    this.emit('callState', 'idle', reason);
  }
}

module.exports = SipUA;
