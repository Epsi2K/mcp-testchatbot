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
                 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'h3', 'h4'],
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

// ── Basic markdown → sanitized HTML ──────────────────────────────────────────
function renderMarkdown(text) {
  var html = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\n\n+/g, '</p><p>')
    .replace(/\n/g, '<br>');

  html = '<p>' + html + '</p>';
  return DOMPurify.sanitize(html, PURIFY_CONFIG);
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
