'use strict';

// ── Security: NO innerHTML for user content. EVER. ──────────────────────────
// JWT stored in module-scoped variable ONLY — NOT in localStorage/sessionStorage
// All user/bot content rendered via textContent or DOMPurify-sanitized markdown

// Fallback if DOMPurify fails to load
if (typeof DOMPurify === 'undefined') {
  window.DOMPurify = {
    sanitize: function(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }
  };
}

// ── State ─────────────────────────────────────────────────────────────────────
var authToken = null;         // Memory-only — NOT in localStorage
var currentUser = null;
var conversationHistory = [];
var isWaiting = false;
var MAX_LENGTH = 1000;

// ── DOMPurify config — ultra-restrictive ─────────────────────────────────────
var PURIFY_CONFIG = {
  ALLOWED_TAGS: ['p', 'strong', 'em', 'ul', 'li', 'ol', 'code', 'pre', 'br',
                 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'h2', 'h3', 'h4'],
  ALLOWED_ATTR: [],
  FORCE_BODY: true,
  SANITIZE_DOM: true,
};

// ── DOM helper ────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }

// ── HTML escape ───────────────────────────────────────────────────────────────
function escapeHtml(str) {
  var d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

// ── Markdown table → HTML ─────────────────────────────────────────────────────
function renderTable(lines) {
  var html = '<table>';
  var inBody = false;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) continue;
    // Separator row (e.g. |---|---|) marks the header/body boundary
    if (/^\|[\s\-|:]+\|$/.test(line)) {
      if (!inBody) { html += '</thead><tbody>'; inBody = true; }
      continue;
    }
    var cells = line.replace(/^\||\|$/g, '').split('|');
    var tag = inBody ? 'td' : 'th';
    if (!inBody && i === 0) html += '<thead>';
    html += '<tr>' + cells.map(function(c) {
      return '<' + tag + '>' + c.trim() + '</' + tag + '>';
    }).join('') + '</tr>';
  }
  if (!inBody) html += '</thead><tbody>';
  html += '</tbody></table>';
  return html;
}

// ── Basic markdown → sanitized HTML ──────────────────────────────────────────
function renderMarkdown(rawText) {
  // Split text into table blocks and text blocks, render each separately
  var lines = rawText.split('\n');
  var blocks = [];
  var i = 0;
  while (i < lines.length) {
    // Table: current line has | AND next line is a separator row
    if (i + 1 < lines.length && /\|/.test(lines[i]) && /^\|[\s\-|:]+\|$/.test(lines[i + 1].trim())) {
      var tableLines = [];
      while (i < lines.length && /\|/.test(lines[i])) { tableLines.push(lines[i]); i++; }
      blocks.push({ type: 'table', lines: tableLines });
    } else {
      var textLines = [];
      while (i < lines.length) {
        if (i + 1 < lines.length && /\|/.test(lines[i]) && /^\|[\s\-|:]+\|$/.test(lines[i + 1].trim())) break;
        textLines.push(lines[i]); i++;
      }
      if (textLines.length) blocks.push({ type: 'text', lines: textLines });
    }
  }

  var parts = blocks.map(function(block) {
    if (block.type === 'table') return renderTable(block.lines);
    var t = block.lines.join('\n');
    t = t
      .replace(/^#{1,2}\s+(.+)$/gm, '<h2>$1</h2>')
      .replace(/^###\s+(.+)$/gm, '<h3>$1</h3>')
      .replace(/^####\s+(.+)$/gm, '<h4>$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`\n]+)`/g, '<code>$1</code>')
      .replace(/\n\n+/g, '</p><p>')
      .replace(/\n/g, '<br>');
    return '<p>' + t + '</p>';
  });

  return DOMPurify.sanitize(parts.join(''), PURIFY_CONFIG);
}

// ── Notifications ─────────────────────────────────────────────────────────────
function showError(msg, duration) {
  duration = duration || 4000;
  var toast = $('error-toast');
  toast.textContent = msg;
  toast.style.display = 'block';
  setTimeout(function() { toast.style.display = 'none'; }, duration);
}

function setStatus(connected) {
  var dot   = $('status-dot');
  var label = $('status-label');
  dot.className = 'status-dot ' + (connected ? 'connected' : 'error');
  label.textContent = connected ? 'Connected' : 'Disconnected';
}

// ── Login ──────────────────────────────────────────────────────────────────────
$('login-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var btn    = $('btn-login');
  var errEl  = $('login-error');
  var username = $('input-username').value;
  var password = $('input-password').value;

  if (!username || !password) {
    errEl.textContent = 'Username and password are required.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in\u2026';
  errEl.style.display = 'none';

  fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, password: password }),
  })
  .then(function(resp) { return resp.json().then(function(data) { return { resp: resp, data: data }; }); })
  .then(function(result) {
    var resp = result.resp, data = result.data;
    if (resp.ok && data.token) {
      authToken   = data.token;
      currentUser = username;

      // Clear sensitive inputs immediately
      $('input-username').value = '';
      $('input-password').value = '';

      // Show app, hide login
      $('login-screen').classList.add('hidden');
      $('app').classList.remove('hidden');

      // Update sidebar — textContent only
      $('session-user').textContent = username;
      $('session-time').textContent = new Date().toLocaleTimeString();
      setStatus(true);
    } else {
      errEl.textContent = (data.error && typeof data.error === 'string') ? data.error : 'Login failed.';
      errEl.style.display = 'block';
    }
  })
  .catch(function() {
    errEl.textContent = 'Connection error. Please try again.';
    errEl.style.display = 'block';
  })
  .finally(function() {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  });
});

// ── Logout ─────────────────────────────────────────────────────────────────────
$('btn-logout').addEventListener('click', function() {
  authToken = null;
  currentUser = null;
  conversationHistory = [];
  $('app').classList.add('hidden');
  $('login-screen').classList.remove('hidden');
  $('messages').innerHTML = '';
  appendWelcome();
  setStatus(false);
});

// ── Reset conversation ─────────────────────────────────────────────────────────
$('btn-reset').addEventListener('click', function() {
  if (!authToken) return;
  conversationHistory = [];
  $('messages').innerHTML = '';
  appendWelcome();
  fetch('/reset', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + authToken },
  }).catch(function() {});
});

// ── Welcome message ────────────────────────────────────────────────────────────
function appendWelcome() {
  var wrap = document.createElement('div');
  wrap.className = 'welcome-msg';
  wrap.id = 'welcome-msg';

  var h3 = document.createElement('h3');
  h3.textContent = 'How can I help you today?';
  wrap.appendChild(h3);

  var p = document.createElement('p');
  p.textContent = 'I can look up employees, run system diagnostics, and retrieve internal documents.';
  wrap.appendChild(p);

  var chips = document.createElement('div');
  chips.className = 'suggestion-chips';

  var prompts = [
    ['Engineering team',   'List all employees in Engineering'],
    ['HR department',      'Who works in HR?'],
    ['Remote work policy', 'Show me the Remote Work Policy'],
    ['System uptime',      'What is the current system uptime?'],
    ['Disk usage',         'Show disk usage'],
  ];

  prompts.forEach(function(pair) {
    var btn = document.createElement('button');
    btn.className = 'chip';
    btn.textContent = pair[0];
    btn.addEventListener('click', function() {
      $('user-input').value = pair[1];
      sendMessage();
    });
    chips.appendChild(btn);
  });

  wrap.appendChild(chips);
  $('messages').appendChild(wrap);
}

// ── Character counter ──────────────────────────────────────────────────────────
$('user-input').addEventListener('input', function() {
  var len     = this.value.length;
  var counter = $('char-counter');
  counter.textContent = len + ' / ' + MAX_LENGTH;
  counter.className   = 'char-counter' + (len > 900 ? (len >= MAX_LENGTH ? ' over' : ' warn') : '');
  this.style.height = 'auto';
  this.style.height = Math.min(this.scrollHeight, 160) + 'px';
});

// ── Send on Enter (Shift+Enter = newline) ──────────────────────────────────────
$('user-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

$('send-btn').addEventListener('click', sendMessage);

// ── Append message bubble ─────────────────────────────────────────────────────
function appendMessage(role, content) {
  var welcome = $('welcome-msg');
  if (welcome) welcome.remove();

  var row    = document.createElement('div');
  row.className = 'msg-row ' + role;

  var avatar = document.createElement('div');
  avatar.className = 'avatar ' + role;
  avatar.textContent = role === 'bot' ? '\uD83E\uDD16' : '\uD83D\uDC64';

  var bubble = document.createElement('div');
  bubble.className = 'bubble ' + role;

  if (role === 'user') {
    bubble.textContent = content;      // NEVER innerHTML for user content
  } else {
    bubble.innerHTML = renderMarkdown(content);   // DOMPurify-sanitized
  }

  row.appendChild(avatar);
  row.appendChild(bubble);
  $('messages').appendChild(row);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function appendTypingIndicator() {
  var welcome = $('welcome-msg');
  if (welcome) welcome.remove();

  var row = document.createElement('div');
  row.className = 'msg-row bot';
  row.id = 'typing-row';

  var avatar = document.createElement('div');
  avatar.className = 'avatar bot';
  avatar.textContent = '\uD83E\uDD16';

  var bubble = document.createElement('div');
  bubble.className = 'bubble bot';

  var indicator = document.createElement('div');
  indicator.className = 'typing-indicator';
  for (var i = 0; i < 3; i++) {
    var dot = document.createElement('div');
    dot.className = 'typing-dot';
    indicator.appendChild(dot);
  }

  bubble.appendChild(indicator);
  row.appendChild(avatar);
  row.appendChild(bubble);
  $('messages').appendChild(row);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function removeTypingIndicator() {
  var el = $('typing-row');
  if (el) el.remove();
}

// ── Send message ───────────────────────────────────────────────────────────────
function sendMessage() {
  if (isWaiting || !authToken) return;

  var input   = $('user-input');
  var message = input.value.trim();
  if (!message) return;
  if (message.length > MAX_LENGTH) {
    showError('Message is too long. Maximum 1000 characters.');
    return;
  }

  appendMessage('user', message);
  input.value = '';
  input.style.height = 'auto';
  $('char-counter').textContent = '0 / ' + MAX_LENGTH;
  $('char-counter').className = 'char-counter';

  isWaiting = true;
  $('send-btn').disabled = true;
  appendTypingIndicator();

  fetch('/chat', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + authToken,
    },
    body: JSON.stringify({ message: message, history: conversationHistory }),
  })
  .then(function(resp) {
    removeTypingIndicator();

    if (resp.status === 401) {
      authToken = null;
      showError('Session expired. Please log in again.');
      setStatus(false);
      setTimeout(function() {
        $('app').classList.add('hidden');
        $('login-screen').classList.remove('hidden');
      }, 1500);
      return null;
    }

    if (resp.status === 429) {
      showError('Too many requests. Please wait a moment.');
      return null;
    }

    return resp.json();
  })
  .then(function(data) {
    if (!data) return;
    if (data.response) {
      appendMessage('bot', data.response);
      conversationHistory = data.history || conversationHistory;
      setStatus(true);
    } else {
      var errMsg = (data.error && typeof data.error === 'string') ? data.error : 'An error occurred.';
      appendMessage('bot', '\u26A0 ' + errMsg);
      setStatus(false);
    }
  })
  .catch(function() {
    removeTypingIndicator();
    appendMessage('bot', '\u26A0 Connection error. Please try again.');
    setStatus(false);
  })
  .finally(function() {
    isWaiting = false;
    $('send-btn').disabled = false;
    $('user-input').focus();
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────
appendWelcome();
