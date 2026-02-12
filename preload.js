/**
 * Preload Script — secure IPC bridge between renderer and main process
 * Exposes a `sipPhone` API on `window.sipPhone`
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sipPhone', {
  // -- Registration --
  register: (config) => ipcRenderer.invoke('sip:register', config),
  unregister: () => ipcRenderer.invoke('sip:unregister'),

  // -- Call controls --
  call: (target) => ipcRenderer.invoke('sip:call', target),
  answer: () => ipcRenderer.invoke('sip:answer'),
  hangup: () => ipcRenderer.invoke('sip:hangup'),
  toggleMute: () => ipcRenderer.invoke('sip:mute'),
  sendDtmf: (digit) => ipcRenderer.invoke('sip:dtmf', digit),

  // -- Microphone audio (renderer → main) --
  sendMicAudio: (arrayBuffer) => ipcRenderer.send('sip:micAudio', arrayBuffer),

  // -- Event listeners --
  onLog: (callback) => {
    ipcRenderer.on('sip:log', (event, type, message) => callback(type, message));
  },
  onStatus: (callback) => {
    ipcRenderer.on('sip:status', (event, state, text) => callback(state, text));
  },
  onCallState: (callback) => {
    ipcRenderer.on('sip:callState', (event, state, info) => callback(state, info));
  },
  onRemoteAudio: (callback) => {
    ipcRenderer.on('sip:remoteAudio', (event, arrayBuffer) => callback(arrayBuffer));
  },
});
