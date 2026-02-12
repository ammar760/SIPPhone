/**
 * RTP Engine — sends and receives RTP audio over raw UDP sockets
 * Handles G.711 µ-law (PCMU, payload type 0) encoding/decoding
 */

const dgram = require('dgram');
const EventEmitter = require('events');
const codec = require('./audio-codec');

const RTP_HEADER_SIZE = 12;
const SAMPLE_RATE = 8000;        // G.711 sample rate
const PTIME = 20;                // packet time in ms
const SAMPLES_PER_PACKET = (SAMPLE_RATE * PTIME) / 1000; // 160 samples

class RtpEngine extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.localPort = 0;
    this.remoteAddress = null;
    this.remotePort = null;
    this.ssrc = Math.floor(Math.random() * 0xFFFFFFFF);
    this.sequenceNumber = Math.floor(Math.random() * 0xFFFF);
    this.timestamp = Math.floor(Math.random() * 0xFFFFFFFF);
    this.payloadType = 0; // PCMU
    this.sendInterval = null;
    this.active = false;
    this.muted = false;
    this.micBuffer = []; // queued mic audio packets
  }

  /**
   * Bind a UDP socket on a random port for RTP
   * @returns {Promise<number>} The local port
   */
  async bind() {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('error', (err) => {
        this.emit('error', err);
      });

      this.socket.on('message', (msg, rinfo) => {
        this._handleIncoming(msg, rinfo);
      });

      // Bind to random port
      this.socket.bind(0, '0.0.0.0', () => {
        const addr = this.socket.address();
        this.localPort = addr.port;
        this.emit('log', `RTP socket bound on port ${this.localPort}`);
        resolve(this.localPort);
      });
    });
  }

  /**
   * Start sending RTP to remote endpoint
   */
  start(remoteAddress, remotePort, payloadType = 0) {
    this.remoteAddress = remoteAddress;
    this.remotePort = remotePort;
    this.payloadType = payloadType;
    this.active = true;

    this.emit('log', `RTP streaming to ${remoteAddress}:${remotePort} (PT=${payloadType})`);

    // Send RTP packets every 20ms
    this.sendInterval = setInterval(() => {
      this._sendPacket();
    }, PTIME);
  }

  /**
   * Stop RTP streaming
   */
  stop() {
    this.active = false;
    if (this.sendInterval) {
      clearInterval(this.sendInterval);
      this.sendInterval = null;
    }
    this.micBuffer = [];
  }

  /**
   * Close the socket completely
   */
  close() {
    this.stop();
    if (this.socket) {
      try { this.socket.close(); } catch (e) {}
      this.socket = null;
    }
  }

  /**
   * Queue microphone PCM data for sending
   * @param {Buffer} pcmData - 16-bit signed LE PCM at 8000Hz
   */
  feedMicAudio(pcmData) {
    if (!this.active || this.muted) return;
    this.micBuffer.push(pcmData);
  }

  /**
   * Set mute state
   */
  setMuted(muted) {
    this.muted = muted;
    if (muted) this.micBuffer = [];
  }

  /**
   * Update remote endpoint (for re-INVITE / hold)
   */
  updateRemote(address, port) {
    this.remoteAddress = address;
    this.remotePort = port;
    this.emit('log', `RTP remote updated to ${address}:${port}`);
  }

  // ---- Private ----

  _sendPacket() {
    if (!this.active || !this.socket || !this.remoteAddress) return;

    let payload;

    if (!this.muted && this.micBuffer.length > 0) {
      // Use real mic audio
      const pcmData = this.micBuffer.shift();
      payload = this.payloadType === 8 ? codec.encodeAlaw(pcmData) : codec.encodeMulaw(pcmData);
    } else {
      // Send silence (µ-law silence = 0xFF, A-law silence = 0xD5)
      payload = Buffer.alloc(SAMPLES_PER_PACKET, this.payloadType === 8 ? 0xD5 : 0xFF);
    }

    const packet = this._buildRtpPacket(payload);

    this.socket.send(packet, 0, packet.length, this.remotePort, this.remoteAddress, (err) => {
      if (err) this.emit('error', err);
    });

    // Advance sequence and timestamp
    this.sequenceNumber = (this.sequenceNumber + 1) & 0xFFFF;
    this.timestamp = (this.timestamp + SAMPLES_PER_PACKET) & 0xFFFFFFFF;
  }

  _buildRtpPacket(payload) {
    const header = Buffer.alloc(RTP_HEADER_SIZE);

    // Byte 0: V=2, P=0, X=0, CC=0 → 0x80
    header[0] = 0x80;
    // Byte 1: M=0, PT
    header[1] = this.payloadType & 0x7F;
    // Bytes 2-3: Sequence number
    header.writeUInt16BE(this.sequenceNumber, 2);
    // Bytes 4-7: Timestamp
    header.writeUInt32BE(this.timestamp, 4);
    // Bytes 8-11: SSRC
    header.writeUInt32BE(this.ssrc, 8);

    return Buffer.concat([header, payload]);
  }

  _handleIncoming(msg, rinfo) {
    if (msg.length < RTP_HEADER_SIZE) return;

    const version = (msg[0] >> 6) & 0x03;
    if (version !== 2) return; // Not RTP

    const pt = msg[1] & 0x7F;
    const payload = msg.slice(RTP_HEADER_SIZE);

    if (payload.length === 0) return;

    // Auto-learn remote address from incoming RTP (symmetric RTP)
    if (!this.remoteAddress || this.remoteAddress === '0.0.0.0') {
      this.remoteAddress = rinfo.address;
      this.remotePort = rinfo.port;
      this.emit('log', `RTP symmetric: learned remote ${rinfo.address}:${rinfo.port}`);
    }

    // Decode to PCM
    let pcmData;
    if (pt === 0) {
      pcmData = codec.decodeMulaw(payload);
    } else if (pt === 8) {
      pcmData = codec.decodeAlaw(payload);
    } else {
      // Unsupported payload type, ignore
      return;
    }

    // Emit decoded audio for playback
    this.emit('audio', pcmData);
  }
}

module.exports = RtpEngine;
