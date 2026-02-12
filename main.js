/**
 * Electron Main Process
 * Runs the SIP UA in the Node.js main process with raw UDP sockets,
 * and bridges audio/events to the renderer via IPC.
 */

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const SipUA = require('./lib/sip-ua');

let mainWindow = null;
let sipUA = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1150,
    height: 750,
    minWidth: 900,
    minHeight: 600,
    title: 'SIP Phone',
    backgroundColor: '#0f1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    icon: path.join(__dirname, 'icon.png'),
    autoHideMenuBar: true,
  });

  mainWindow.loadFile('index.html');

  mainWindow.on('closed', () => {
    mainWindow = null;
    if (sipUA) {
      sipUA.stop();
      sipUA = null;
    }
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (sipUA) {
    sipUA.stop();
    sipUA = null;
  }
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ===================================================================
//  IPC Handlers — bridge between renderer UI and SIP UA
// ===================================================================

function send(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

function setupSipUA(config) {
  if (sipUA) {
    sipUA.stop();
  }

  sipUA = new SipUA(config);

  // Forward logs to renderer
  sipUA.on('log', (type, message) => {
    send('sip:log', type, message);
  });

  // Forward status changes
  sipUA.on('status', (state, text) => {
    send('sip:status', state, text);
  });

  // Forward call state changes
  sipUA.on('callState', (state, info) => {
    send('sip:callState', state, info);
  });

  // Forward remote audio (PCM data) to renderer for playback
  sipUA.on('remoteAudio', (pcmBuffer) => {
    // Send as ArrayBuffer to renderer
    send('sip:remoteAudio', pcmBuffer.buffer.slice(
      pcmBuffer.byteOffset,
      pcmBuffer.byteOffset + pcmBuffer.byteLength
    ));
  });

  return sipUA;
}

// -- Register/Unregister --
ipcMain.handle('sip:register', async (event, config) => {
  try {
    const ua = setupSipUA(config);
    await ua.register();
    return { ok: true };
  } catch (err) {
    send('sip:log', 'error', `Register error: ${err.message}`);
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('sip:unregister', async () => {
  if (sipUA) {
    sipUA.unregister();
  }
  return { ok: true };
});

// -- Call controls --
ipcMain.handle('sip:call', async (event, target) => {
  if (!sipUA) return { ok: false, error: 'Not connected' };
  await sipUA.invite(target);
  return { ok: true };
});

ipcMain.handle('sip:answer', async () => {
  if (!sipUA) return { ok: false, error: 'Not connected' };
  await sipUA.answerIncoming();
  return { ok: true };
});

ipcMain.handle('sip:hangup', async () => {
  if (!sipUA) return { ok: false, error: 'Not connected' };
  sipUA.hangup();
  return { ok: true };
});

ipcMain.handle('sip:mute', async () => {
  if (!sipUA) return { muted: false };
  const muted = sipUA.toggleMute();
  return { muted };
});

ipcMain.handle('sip:dtmf', async (event, digit) => {
  if (!sipUA) return;
  sipUA.sendDtmf(digit);
});

// -- Microphone audio from renderer --
ipcMain.on('sip:micAudio', (event, arrayBuffer) => {
  if (sipUA) {
    sipUA.feedMicAudio(Buffer.from(arrayBuffer));
  }
});
