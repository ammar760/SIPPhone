/**
 * G.711 µ-law (PCMU) and A-law (PCMA) codec
 * Converts between 16-bit linear PCM and 8-bit G.711 samples
 */

// ===== µ-law (G.711u / PCMU — RTP payload type 0) =====

const MULAW_BIAS = 0x84;
const MULAW_CLIP = 32635;

const mulawEncodeTable = [
  0,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,
  4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
  5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
];

/**
 * Encode a single 16-bit signed PCM sample to 8-bit µ-law
 */
function pcmToMulaw(sample) {
  let sign = (sample >> 8) & 0x80;
  if (sign !== 0) sample = -sample;
  if (sample > MULAW_CLIP) sample = MULAW_CLIP;
  sample = sample + MULAW_BIAS;
  let exponent = mulawEncodeTable[(sample >> 7) & 0xFF];
  let mantissa = (sample >> (exponent + 3)) & 0x0F;
  let mulawByte = ~(sign | (exponent << 4) | mantissa);
  return mulawByte & 0xFF;
}

/**
 * Decode a single 8-bit µ-law sample to 16-bit signed PCM
 */
function mulawToPcm(mulawByte) {
  mulawByte = ~mulawByte & 0xFF;
  let sign = (mulawByte & 0x80);
  let exponent = (mulawByte >> 4) & 0x07;
  let mantissa = mulawByte & 0x0F;
  let sample = ((mantissa << 3) + MULAW_BIAS) << exponent;
  sample -= MULAW_BIAS;
  if (sign !== 0) sample = -sample;
  return sample;
}

// ===== A-law (G.711a / PCMA — RTP payload type 8) =====

/**
 * Encode a single 16-bit signed PCM sample to 8-bit A-law
 */
function pcmToAlaw(sample) {
  let sign = 0;
  if (sample < 0) {
    sign = 0x80;
    sample = -sample;
  }

  if (sample > 32767) sample = 32767;

  let exponent, mantissa, companded;

  if (sample >= 256) {
    exponent = Math.floor(Math.log2(sample)) - 4;
    if (exponent > 7) exponent = 7;
    mantissa = (sample >> (exponent + 3)) & 0x0F;
    companded = (exponent << 4) | mantissa;
  } else {
    companded = sample >> 4;
  }

  return (companded | sign) ^ 0x55;
}

/**
 * Decode a single 8-bit A-law sample to 16-bit signed PCM
 */
function alawToPcm(alawByte) {
  alawByte ^= 0x55;
  let sign = alawByte & 0x80;
  let exponent = (alawByte >> 4) & 0x07;
  let mantissa = alawByte & 0x0F;

  let sample;
  if (exponent === 0) {
    sample = (mantissa << 4) + 8;
  } else {
    sample = ((mantissa << 3) + 0x84) << (exponent);
  }

  if (sign) sample = -sample;
  return sample;
}

// ===== Buffer-level encode/decode =====

/**
 * Encode Int16 PCM buffer to µ-law buffer
 * @param {Buffer|Int16Array} pcmBuf - 16-bit signed PCM samples
 * @returns {Buffer} - 8-bit µ-law encoded
 */
function encodeMulaw(pcmBuf) {
  const samples = pcmBuf instanceof Int16Array ? pcmBuf : new Int16Array(pcmBuf.buffer, pcmBuf.byteOffset, pcmBuf.byteLength / 2);
  const out = Buffer.alloc(samples.length);
  for (let i = 0; i < samples.length; i++) {
    out[i] = pcmToMulaw(samples[i]);
  }
  return out;
}

/**
 * Decode µ-law buffer to Int16 PCM buffer
 * @param {Buffer} mulawBuf - 8-bit µ-law encoded
 * @returns {Buffer} - 16-bit signed PCM (little-endian)
 */
function decodeMulaw(mulawBuf) {
  const out = Buffer.alloc(mulawBuf.length * 2);
  for (let i = 0; i < mulawBuf.length; i++) {
    const sample = mulawToPcm(mulawBuf[i]);
    out.writeInt16LE(sample, i * 2);
  }
  return out;
}

/**
 * Encode Int16 PCM buffer to A-law buffer
 */
function encodeAlaw(pcmBuf) {
  const samples = pcmBuf instanceof Int16Array ? pcmBuf : new Int16Array(pcmBuf.buffer, pcmBuf.byteOffset, pcmBuf.byteLength / 2);
  const out = Buffer.alloc(samples.length);
  for (let i = 0; i < samples.length; i++) {
    out[i] = pcmToAlaw(samples[i]);
  }
  return out;
}

/**
 * Decode A-law buffer to Int16 PCM buffer
 */
function decodeAlaw(alawBuf) {
  const out = Buffer.alloc(alawBuf.length * 2);
  for (let i = 0; i < alawBuf.length; i++) {
    const sample = alawToPcm(alawBuf[i]);
    out.writeInt16LE(sample, i * 2);
  }
  return out;
}

module.exports = {
  pcmToMulaw, mulawToPcm,
  pcmToAlaw, alawToPcm,
  encodeMulaw, decodeMulaw,
  encodeAlaw, decodeAlaw,
};
