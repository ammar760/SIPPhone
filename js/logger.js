/**
 * Logger module — handles structured logging to the UI panel
 */
class SIPLogger {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.logs = [];
    this.currentFilter = 'all';
    this.maxLogs = 2000;
  }

  /**
   * Add a log entry
   * @param {'info'|'sip'|'call'|'warn'|'error'|'debug'} type
   * @param {string} message
   */
  log(type, message) {
    const now = new Date();
    const time = now.toTimeString().split(' ')[0]; // HH:MM:SS
    const entry = { type, message, time, timestamp: now.toISOString() };
    this.logs.push(entry);

    // Trim old logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // Only render if matches current filter
    if (this.currentFilter === 'all' || this._matchesFilter(entry, this.currentFilter)) {
      this._renderEntry(entry);
    }

    // Also log to browser console
    const consoleFn = type === 'error' ? console.error : type === 'warn' ? console.warn : console.log;
    consoleFn(`[${type.toUpperCase()}] ${message}`);
  }

  info(msg) { this.log('info', msg); }
  sip(msg) { this.log('sip', msg); }
  call(msg) { this.log('call', msg); }
  warn(msg) { this.log('warn', msg); }
  error(msg) { this.log('error', msg); }
  debug(msg) { this.log('debug', msg); }

  _matchesFilter(entry, filter) {
    if (filter === 'all') return true;
    if (filter === 'error') return entry.type === 'error' || entry.type === 'warn';
    return entry.type === filter;
  }

  _renderEntry(entry) {
    const el = document.createElement('div');
    el.className = `log-entry log-${entry.type}`;
    el.setAttribute('data-type', entry.type);

    const badgeClass = {
      info: 'badge-info', sip: 'badge-sip', call: 'badge-call',
      warn: 'badge-warn', error: 'badge-error', debug: 'badge-debug'
    }[entry.type] || 'badge-info';

    el.innerHTML = `
      <span class="log-time">${entry.time}</span>
      <span class="log-badge ${badgeClass}">${entry.type}</span>
      <span class="log-message">${this._escapeHtml(entry.message)}</span>
    `;

    this.container.appendChild(el);
    this.container.scrollTop = this.container.scrollHeight;
  }

  setFilter(filter) {
    this.currentFilter = filter;
    this._rerenderAll();
  }

  _rerenderAll() {
    this.container.innerHTML = '';
    const filtered = this.logs.filter(e => this._matchesFilter(e, this.currentFilter));
    filtered.forEach(entry => this._renderEntry(entry));
  }

  clear() {
    this.logs = [];
    this.container.innerHTML = '';
  }

  export() {
    const text = this.logs.map(e =>
      `[${e.timestamp}] [${e.type.toUpperCase().padEnd(5)}] ${e.message}`
    ).join('\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sip-phone-logs-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  _escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
}
