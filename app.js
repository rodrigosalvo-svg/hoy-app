/* ========================= UTILIDADES ========================= */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

function todayStr(offsetDays = 0) {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  d.setHours(0, 0, 0, 0);
  return d.toISOString().slice(0, 10);
}

function humanDate(dateStr) {
  if (!dateStr) return '';
  const today = todayStr();
  const tomorrow = todayStr(1);
  if (dateStr === today) return 'Hoy';
  if (dateStr === tomorrow) return 'Mañana';
  const [y, m, d] = dateStr.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  return dt.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' });
}

function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 1800);
}

/* ========================= ALMACENAMIENTO ========================= */
const Store = {
  get(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) { return fallback; }
  },
  set(key, value) { localStorage.setItem(key, JSON.stringify(value)); }
};

let tasks = Store.get('hoy_tasks', []);
let notes = Store.get('hoy_notes', []);
let streak = Store.get('hoy_streak', { count: 0, lastDate: null });
let settings = Store.get('hoy_settings', { lockEnabled: false });
let lockMeta = Store.get('hoy_lockmeta', null); // { salt, verifierIv, verifierCt }

function saveTasks() { Store.set('hoy_tasks', tasks); }
function saveNotes() { Store.set('hoy_notes', notes); }
function saveStreak() { Store.set('hoy_streak', streak); }
function saveSettings() { Store.set('hoy_settings', settings); }
function saveLockMeta() { Store.set('hoy_lockmeta', lockMeta); }

/* ========================= CIFRADO (PIN) ========================= */
const Crypto = {
  sessionKey: null, // CryptoKey en memoria, nunca persistido

  buf2b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); },
  b642buf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },

  async deriveKey(pin, saltB64) {
    const salt = this.b642buf(saltB64);
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async setupPin(pin) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = this.buf2b64(saltBytes);
    const key = await this.deriveKey(pin, saltB64);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode('OK'));
    lockMeta = { salt: saltB64, verifierIv: this.buf2b64(iv), verifierCt: this.buf2b64(ct) };
    saveLockMeta();
    this.sessionKey = key;
    return key;
  },

  async tryUnlock(pin) {
    if (!lockMeta) return false;
    try {
      const key = await this.deriveKey(pin, lockMeta.salt);
      const iv = this.b642buf(lockMeta.verifierIv);
      const ct = this.b642buf(lockMeta.verifierCt);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      const text = new TextDecoder().decode(plain);
      if (text === 'OK') { this.sessionKey = key; return true; }
      return false;
    } catch (e) { return false; }
  },

  lock() { this.sessionKey = null; },

  async encryptBuffer(buffer) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.sessionKey, buffer);
    return { iv, ciphertext };
  },

  async decryptBuffer(payload) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: payload.iv }, this.sessionKey, payload.ciphertext);
  },

  async encryptText(text) {
    if (!this.sessionKey) return text;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.sessionKey, enc.encode(text));
    return 'enc:' + this.buf2b64(iv) + ':' + this.buf2b64(ct);
  },

  async decryptText(payload) {
    if (typeof payload !== 'string' || !payload.startsWith('enc:')) return payload;
    if (!this.sessionKey) return '••••••••';
    const [, ivB64, ctB64] = payload.split(':');
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: this.b642buf(ivB64) }, this.sessionKey, this.b642buf(ctB64)
      );
      return new TextDecoder().decode(plain);
    } catch (e) { return '⚠️ No se pudo descifrar'; }
  }
};

/* ========================= AUDIO (IndexedDB) ========================= */
const AudioDB = {
  db: null,
  open() {
    if (this.db) return Promise.resolve(this.db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('hoy_audio_db', 1);
      req.onupgradeneeded = () => req.result.createObjectStore('audio');
      req.onsuccess = () => { this.db = req.result; resolve(this.db); };
      req.onerror = () => reject(req.error);
    });
  },
  async put(id, data) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('audio', 'readwrite');
      tx.objectStore('audio').put(data, id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
  async get(id) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const req = db.transaction('audio', 'readonly').objectStore('audio').get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },
  async delete(id) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('audio', 'readwrite');
      tx.objectStore('audio').delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
};

/* ========================= MODALES (cerrar tocando afuera / boton atras) ========================= */
let modalOpenCount = 0;
let suppressHistoryPop = false;

function openModal(sel) {
  show(sel);
  history.pushState({ hoyModalOpen: true }, '');
  modalOpenCount++;
}

function closeModal(sel) {
  hide(sel);
  if (modalOpenCount > 0) {
    modalOpenCount--;
    if (!suppressHistoryPop) history.back();
  }
}

function show(sel) { $(sel).classList.remove('hidden'); }
function hide(sel) { $(sel).classList.add('hidden'); }

window.addEventListener('popstate', () => {
  if (modalOpenCount === 0) return;
  suppressHistoryPop = true;
  const overlays = $$('.modal-overlay').filter(o => !o.classList.contains('hidden'));
  const top = overlays[overlays.length - 1];
  const closeBtn = top && top.querySelector('.icon-btn');
  if (closeBtn) closeBtn.click();
  modalOpenCount = Math.max(0, modalOpenCount - 1);
  suppressHistoryPop = false;
});

$$('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', (e) => {
    if (e.target !== overlay) return;
    const closeBtn = overlay.querySelector('.icon-btn');
    if (closeBtn) closeBtn.click();
  });
});

/* ========================= RACHA ========================= */
function registerCompletionToday() {
  const today = todayStr();
  if (streak.lastDate === today) return;
  const yesterday = todayStr(-1);
  streak.count = (streak.lastDate === yesterday) ? streak.count + 1 : 1;
  streak.lastDate = today;
  saveStreak();
  renderStreak();
}

function renderStreak() {
  $('#streakCount').textContent = streak.count || 0;
  const chip = $('#streakChip');
  const active = streak.lastDate === todayStr() || streak.lastDate === todayStr(-1);
  chip.classList.toggle('on', !!streak.count && active);
}

/* ========================= NAVEGACIÓN ========================= */
function switchView(name) {
  $$('.view').forEach(v => v.classList.remove('active'));
  $('#view-' + name).classList.add('active');
  $$('.navbtn').forEach(b => b.classList.toggle('nav-active', b.dataset.view === name));
  $('#quickCapture').classList.toggle('hidden', name === 'notas');
  if (name === 'notas') renderNotasView();
  if (name === 'tareas') renderTareas();
  if (name === 'hoy') renderHoy();
}

$$('.navbtn').forEach(btn => btn.addEventListener('click', () => switchView(btn.dataset.view)));

/* ========================= VISTA HOY ========================= */
function renderHoy() {
  const today = todayStr();
  const overdue = tasks.filter(t => !t.done && t.date && t.date < today);
  const todays = tasks.filter(t => !t.done && t.date === today);
  const doneToday = tasks.filter(t => t.done && t.date === today);

  $('#overdueBlock').classList.toggle('hidden', overdue.length === 0);
  $('#overdueList').innerHTML = overdue.map(t => taskItemHtml(t, true)).join('');

  $('#todayList').innerHTML = todays.map(t => taskItemHtml(t, false)).join('');
  $('#todayEmpty').classList.toggle('hidden', todays.length !== 0);

  $('#doneBlock').classList.toggle('hidden', doneToday.length === 0);
  $('#doneTodayCount').textContent = doneToday.length;
  $('#doneTodayList').innerHTML = doneToday.map(t => taskItemHtml(t, false)).join('');

  const totalRelevant = todays.length + doneToday.length;
  const pct = totalRelevant ? Math.round((doneToday.length / totalRelevant) * 100) : 0;
  $('#todayProgressFill').style.width = pct + '%';
  $('#todayProgressLabel').textContent = totalRelevant
    ? `${doneToday.length}/${totalRelevant} completadas hoy (${pct}%)`
    : 'Sin tareas para hoy';

  bindTaskListEvents();
  renderStreak();
}

function taskItemHtml(t, isOverdue) {
  const badgeClass = isOverdue ? 'task-date-badge overdue-badge' : 'task-date-badge';
  const dateLabel = t.date ? humanDate(t.date) : '';
  return `
  <li class="task-item ${t.done ? 'done' : ''} ${isOverdue ? 'overdue' : ''}" data-id="${t.id}">
    <button class="check ${t.done ? 'checked' : ''}" data-action="toggle">${t.done ? '✓' : ''}</button>
    <div class="task-text">${escapeHtml(t.text)}</div>
    ${dateLabel ? `<div class="${badgeClass}">${dateLabel}</div>` : ''}
    <button class="task-del" data-action="delete">✕</button>
  </li>`;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function bindTaskListEvents() {
  $$('.task-item').forEach(li => {
    const id = li.dataset.id;
    const toggleBtn = li.querySelector('[data-action="toggle"]');
    const delBtn = li.querySelector('[data-action="delete"]');
    toggleBtn.onclick = () => toggleTask(id);
    delBtn.onclick = () => removeTask(id, li);
  });
}

function toggleTask(id) {
  const t = tasks.find(x => x.id === id);
  if (!t) return;
  t.done = !t.done;
  t.doneAt = t.done ? Date.now() : null;
  if (t.done) registerCompletionToday();
  saveTasks();
  renderHoy();
  renderTareas();
}

function removeTask(id, li) {
  if (li) {
    li.classList.add('removing');
    setTimeout(() => { tasks = tasks.filter(t => t.id !== id); saveTasks(); renderHoy(); renderTareas(); }, 200);
  } else {
    tasks = tasks.filter(t => t.id !== id);
    saveTasks(); renderHoy(); renderTareas();
  }
}

$('#toggleDoneToday').addEventListener('click', () => {
  $('#doneTodayList').classList.toggle('hidden');
});

/* ========================= VISTA TAREAS ========================= */
const GROUP_DEFS = [
  { key: 'vencidas', label: '⚠ Vencidas', test: (t) => !t.done && t.date && t.date < todayStr() },
  { key: 'hoy', label: 'Hoy', test: (t) => !t.done && t.date === todayStr() },
  { key: 'manana', label: 'Mañana', test: (t) => !t.done && t.date === todayStr(1) },
  { key: 'semana', label: 'Esta semana', test: (t) => !t.done && t.date && t.date > todayStr(1) && t.date <= todayStr(7) },
  { key: 'futuro', label: 'Más adelante', test: (t) => !t.done && t.date && t.date > todayStr(7) },
  { key: 'sinfecha', label: 'Sin fecha', test: (t) => !t.done && !t.date },
  { key: 'completadas', label: '✓ Completadas', test: (t) => t.done },
];

let collapsedGroups = Store.get('hoy_collapsed_groups', { completadas: true });

function renderTareas() {
  const container = $('#groupsContainer');
  container.innerHTML = GROUP_DEFS.map(g => {
    const items = tasks.filter(g.test);
    if (items.length === 0) return '';
    const collapsed = !!collapsedGroups[g.key];
    return `
    <div class="task-group">
      <div class="group-header" data-group="${g.key}">
        <span class="group-title">${g.label}</span>
        <span class="group-count">${items.length}</span>
      </div>
      <div class="group-body ${collapsed ? 'collapsed' : ''}" id="group-${g.key}">
        ${items.map(t => taskItemHtml(t, g.key === 'vencidas')).join('')}
      </div>
    </div>`;
  }).join('') + `<button class="add-task-btn" id="addTaskBtn">+ Agregar tarea con fecha</button>`;

  $$('.group-header').forEach(h => {
    h.addEventListener('click', () => {
      const key = h.dataset.group;
      collapsedGroups[key] = !collapsedGroups[key];
      Store.set('hoy_collapsed_groups', collapsedGroups);
      renderTareas();
    });
  });
  bindTaskListEvents();
  $('#addTaskBtn').addEventListener('click', () => openTaskModal());
}

/* ---- Modal de tarea (vista Tareas) ---- */
function openTaskModal() {
  $('#taskTextInput').value = '';
  $('#taskDateInput').value = todayStr();
  openModal('#taskModal');
  setTimeout(() => $('#taskTextInput').focus(), 50);
}
$('#closeTaskModal').addEventListener('click', () => closeModal('#taskModal'));
$('#taskNoDateBtn').addEventListener('click', () => { $('#taskDateInput').value = ''; });
$('#saveTaskBtn').addEventListener('click', () => {
  const text = $('#taskTextInput').value.trim();
  if (!text) { toast('Escribe algo primero'); return; }
  tasks.push({ id: uid(), text, date: $('#taskDateInput').value || null, done: false, createdAt: Date.now(), doneAt: null });
  saveTasks();
  closeModal('#taskModal');
  renderTareas(); renderHoy();
  toast('Tarea agregada');
});

/* ========================= VISTA NOTAS ========================= */
let notesUnlockedThisSession = false;
let activeNoteId = null;
let activeCategoryFilter = 'Todas';

function renderNotasView() {
  if (settings.lockEnabled && !lockMeta) settings.lockEnabled = false; // estado inconsistente de seguridad

  if (!settings.lockEnabled) {
    // Sin PIN configurado: si es la primera vez que se abre notas y no hay decisión guardada, ofrecer setup
    if (Store.get('hoy_pin_decision', null) === null) {
      show('#pinSetupScreen'); hide('#notesLockScreen'); hide('#notesContent');
      return;
    }
    hide('#pinSetupScreen'); hide('#notesLockScreen');
    show('#notesContent');
    renderNotesList();
    return;
  }

  // Lock habilitado
  if (Crypto.sessionKey && notesUnlockedThisSession) {
    hide('#pinSetupScreen'); hide('#notesLockScreen'); show('#notesContent');
    renderNotesList();
  } else {
    hide('#pinSetupScreen'); hide('#notesContent'); show('#notesLockScreen');
    setTimeout(() => $('#unlockPinInput').focus(), 50);
  }
}

$('#setupPinBtn').addEventListener('click', async () => {
  const p1 = $('#setupPinInput').value.trim();
  const p2 = $('#setupPinInput2').value.trim();
  if (p1.length < 4 || p1 !== p2) {
    $('#setupError').textContent = p1.length < 4 ? 'El PIN debe tener al menos 4 dígitos' : 'Los PIN no coinciden';
    show('#setupError');
    return;
  }
  hide('#setupError');
  await Crypto.setupPin(p1);
  settings.lockEnabled = true;
  saveSettings();
  Store.set('hoy_pin_decision', 'protected');
  notesUnlockedThisSession = true;
  toast('Notas protegidas con PIN');
  renderNotasView();
});

$('#skipPinBtn').addEventListener('click', () => {
  settings.lockEnabled = false;
  saveSettings();
  Store.set('hoy_pin_decision', 'skipped');
  renderNotasView();
});

$('#unlockBtn').addEventListener('click', doUnlock);
$('#unlockPinInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doUnlock(); });
async function doUnlock() {
  const pin = $('#unlockPinInput').value.trim();
  const ok = await Crypto.tryUnlock(pin);
  if (ok) {
    notesUnlockedThisSession = true;
    $('#unlockPinInput').value = '';
    hide('#unlockError');
    renderNotasView();
  } else {
    show('#unlockError');
  }
}

$('#lockNotesBtn').addEventListener('click', () => {
  Crypto.lock();
  notesUnlockedThisSession = false;
  renderNotasView();
  toast('Notas bloqueadas');
});

$$('#categoryFilter .chip').forEach(chip => {
  chip.addEventListener('click', () => {
    activeCategoryFilter = chip.dataset.cat;
    $$('#categoryFilter .chip').forEach(c => c.classList.toggle('chip-active', c === chip));
    renderNotesList();
  });
});

$('#notesSearch').addEventListener('input', renderNotesList);

const CAT_ICON = { Claves: '🔑', Direcciones: '📍', Fechas: '📅', General: '📝', Audio: '🎙️' };

async function renderNotesList() {
  const search = $('#notesSearch').value.trim().toLowerCase();
  let list = notes.slice().sort((a, b) => b.updatedAt - a.updatedAt);
  if (activeCategoryFilter !== 'Todas') list = list.filter(n => n.category === activeCategoryFilter);

  const rows = [];
  for (const n of list) {
    if (n.isAudio) {
      if (search && !n.title.toLowerCase().includes(search)) continue;
      rows.push(`
        <li class="note-card audio-card" data-cat="${n.category}" data-id="${n.id}">
          <div class="note-title-row">
            <span class="note-title">🎙️ ${escapeHtml(n.title)}</span>
            <button class="task-del" data-audio-del="${n.id}">✕</button>
          </div>
          <audio controls class="audio-player" data-audio-id="${n.id}"></audio>
        </li>`);
      continue;
    }
    const plainContent = await Crypto.decryptText(n.content);
    const hay = (n.title + ' ' + plainContent).toLowerCase();
    if (search && !hay.includes(search)) continue;
    const snippet = plainContent.replace(/\n/g, ' ').slice(0, 60);
    rows.push(`
      <li class="note-card" data-cat="${n.category}" data-id="${n.id}">
        <div class="note-title-row">
          <span class="note-title">${escapeHtml(n.title || '(sin título)')}</span>
          <span class="note-cat-badge">${CAT_ICON[n.category] || ''} ${n.category}</span>
        </div>
        <div class="note-snippet">${escapeHtml(snippet)}</div>
      </li>`);
  }
  $('#notesList').innerHTML = rows.join('');
  $('#notesEmpty').classList.toggle('hidden', notes.length !== 0);

  $$('.note-card').forEach(card => {
    if (card.classList.contains('audio-card')) return;
    card.addEventListener('click', () => openNoteModal(card.dataset.id));
  });

  $$('[data-audio-del]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.audioDel;
      notes = notes.filter(n => n.id !== id);
      saveNotes();
      try { await AudioDB.delete(id); } catch (e2) { /* ya no está, no importa */ }
      renderNotesList();
      toast('Nota de voz eliminada');
    });
  });

  for (const el of $$('.audio-player')) {
    loadAudioSrc(el, el.dataset.audioId);
  }
}

async function loadAudioSrc(el, id) {
  try {
    const payload = await AudioDB.get(id);
    if (!payload) return;
    let blob;
    if (payload.encrypted) {
      if (!Crypto.sessionKey) return;
      const buffer = await Crypto.decryptBuffer(payload);
      blob = new Blob([buffer], { type: payload.mime });
    } else {
      blob = payload.blob;
    }
    el.src = URL.createObjectURL(blob);
  } catch (e) { /* audio no disponible */ }
}

/* ---- Modal de nota ---- */
async function openNoteModal(id) {
  activeNoteId = id || null;
  const note = id ? notes.find(n => n.id === id) : null;
  $('#noteModalTitle').textContent = note ? 'Editar nota' : 'Nueva nota';
  $('#noteTitleInput').value = note ? note.title : '';
  $('#noteCategoryInput').value = note ? note.category : 'General';
  $('#noteContentInput').value = note ? await Crypto.decryptText(note.content) : '';
  $('#deleteNoteBtn').classList.toggle('hidden', !note);
  openModal('#noteModal');
  setTimeout(() => $('#noteTitleInput').focus(), 50);
}

$('#newNoteBtn').addEventListener('click', () => openNoteModal(null));
$('#closeNoteModal').addEventListener('click', () => closeModal('#noteModal'));

$('#saveNoteBtn').addEventListener('click', async () => {
  const title = $('#noteTitleInput').value.trim();
  const category = $('#noteCategoryInput').value;
  const contentPlain = $('#noteContentInput').value;
  if (!title && !contentPlain) { toast('Escribe algo primero'); return; }
  const content = await Crypto.encryptText(contentPlain);

  if (activeNoteId) {
    const note = notes.find(n => n.id === activeNoteId);
    Object.assign(note, { title, category, content, updatedAt: Date.now() });
  } else {
    notes.push({ id: uid(), title, category, content, createdAt: Date.now(), updatedAt: Date.now() });
  }
  saveNotes();
  closeModal('#noteModal');
  renderNotesList();
  toast('Nota guardada');
});

$('#deleteNoteBtn').addEventListener('click', () => {
  notes = notes.filter(n => n.id !== activeNoteId);
  saveNotes();
  closeModal('#noteModal');
  renderNotesList();
  toast('Nota eliminada');
});

/* ========================= DESBLOQUEO RAPIDO ========================= */
// Si el PIN esta activado pero aun no se desbloqueo en esta sesion, pide el PIN
// antes de guardar una nota/audio para no guardarlos sin cifrar por error.
function requireUnlock() {
  if (!settings.lockEnabled || Crypto.sessionKey) return Promise.resolve(true);
  return new Promise((resolve) => {
    $('#quickUnlockPin').value = '';
    hide('#quickUnlockError');
    openModal('#quickUnlockModal');
    setTimeout(() => $('#quickUnlockPin').focus(), 50);

    function cleanup() {
      closeModal('#quickUnlockModal');
      $('#quickUnlockBtn').onclick = null;
      $('#closeQuickUnlock').onclick = null;
      $('#quickUnlockPin').onkeydown = null;
    }
    async function tryIt() {
      const ok = await Crypto.tryUnlock($('#quickUnlockPin').value.trim());
      if (ok) { notesUnlockedThisSession = true; cleanup(); resolve(true); }
      else { show('#quickUnlockError'); }
    }
    $('#quickUnlockBtn').onclick = tryIt;
    $('#quickUnlockPin').onkeydown = (e) => { if (e.key === 'Enter') tryIt(); };
    $('#closeQuickUnlock').onclick = () => { cleanup(); resolve(false); };
  });
}

/* ========================= CAPTURA RÁPIDA ========================= */
let qcType = 'tarea';
let qcWhen = 'hoy';

$$('.qc-type').forEach(btn => {
  btn.addEventListener('click', () => {
    qcType = btn.dataset.type;
    $$('.qc-type').forEach(b => b.classList.toggle('qc-type-active', b === btn));
    $('#qcWhenRow').classList.toggle('hidden', qcType !== 'tarea');
    $('#qcForm').classList.toggle('hidden', qcType === 'audio');
    $('#qcAudioRow').classList.toggle('hidden', qcType !== 'audio');
    if (qcType === 'audio' && !window.SpeechRecognitionCtorChecked) {
      window.SpeechRecognitionCtorChecked = true;
      if (!(window.SpeechRecognition || window.webkitSpeechRecognition)) {
        toast('Este navegador solo guardará el audio, sin transcribirlo a texto');
      }
    }
    $('#qcInput').placeholder = qcType === 'tarea' ? 'Anota una tarea rápida...' : 'Anota una nota rápida...';
  });
});

$$('#qcWhenRow .chip').forEach(chip => {
  chip.addEventListener('click', () => {
    qcWhen = chip.dataset.when;
    $$('#qcWhenRow .chip').forEach(c => c.classList.toggle('chip-active', c === chip));
  });
});

$('#qcForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#qcInput');
  const text = input.value.trim();
  if (!text) return;

  if (qcType === 'tarea') {
    let date = todayStr();
    if (qcWhen === 'manana') date = todayStr(1);
    if (qcWhen === 'sinfecha') date = null;
    tasks.push({ id: uid(), text, date, done: false, createdAt: Date.now(), doneAt: null });
    saveTasks();
    renderHoy(); renderTareas();
    toast('Tarea agregada ✅');
  } else {
    const unlocked = await requireUnlock();
    if (!unlocked) { toast('Nota no guardada'); return; }
    const content = await Crypto.encryptText(text);
    notes.push({ id: uid(), title: text.slice(0, 40), category: 'General', content, createdAt: Date.now(), updatedAt: Date.now() });
    saveNotes();
    toast('Nota guardada 🗒️');
  }
  input.value = '';
  input.focus();
});

/* ---- Nota de voz ---- */
let mediaRecorder = null;
let audioChunks = [];
let recordStartTime = null;
let recordTimerInterval = null;
let speechRecognizer = null;
let transcriptFinal = '';

const SpeechRecognitionCtor = window.SpeechRecognition || window.webkitSpeechRecognition;

function startTranscription() {
  if (!SpeechRecognitionCtor) {
    toast('Este navegador no transcribe voz automáticamente');
    return;
  }
  transcriptFinal = '';
  try {
    speechRecognizer = new SpeechRecognitionCtor();
    speechRecognizer.lang = 'es-CL';
    speechRecognizer.continuous = true;
    speechRecognizer.interimResults = true;
    speechRecognizer.onresult = (e) => {
      let interim = '';
      for (let i = e.resultIndex; i < e.results.length; i++) {
        const chunk = e.results[i][0].transcript;
        if (e.results[i].isFinal) transcriptFinal += chunk + ' ';
        else interim += chunk;
      }
      $('#qcTranscriptPreview').classList.remove('hidden');
      $('#qcTranscriptPreview').textContent = '💬 ' + (transcriptFinal + interim).trim();
    };
    speechRecognizer.onerror = (e) => { console.warn('Transcripción: ' + e.error); };
    speechRecognizer.start();
  } catch (e) { speechRecognizer = null; }
}

// Espera a que el reconocimiento termine de verdad: al llamar stop(), los
// ultimos resultados finales llegan de forma asincrona un instante despues,
// asi que hay que esperar el evento onend antes de leer transcriptFinal.
function stopTranscriptionAndWait() {
  return new Promise((resolve) => {
    $('#qcTranscriptPreview').classList.add('hidden');
    $('#qcTranscriptPreview').textContent = '';
    if (!speechRecognizer) { resolve(); return; }
    const r = speechRecognizer;
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    r.onend = finish;
    r.onerror = finish;
    setTimeout(finish, 1500);
    try { r.stop(); } catch (e) { finish(); }
  });
}

async function toggleRecording() {
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    mediaRecorder.stop();
    return;
  }
  const unlocked = await requireUnlock();
  if (!unlocked) return;

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    toast('Tu navegador no permite grabar audio aquí');
    return;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    toast('No se pudo acceder al micrófono');
    return;
  }

  audioChunks = [];
  mediaRecorder = new MediaRecorder(stream);
  mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) audioChunks.push(e.data); };
  mediaRecorder.onstop = async () => {
    stream.getTracks().forEach(t => t.stop());
    await stopTranscriptionAndWait();
    clearInterval(recordTimerInterval);
    $('#qcRecordTimer').classList.add('hidden');
    $('#qcRecordBtn').textContent = '🎙️ Toca para grabar';
    $('#qcRecordBtn').classList.remove('recording');
    const durationMs = Date.now() - recordStartTime;
    if (durationMs < 500) { toast('Grabación muy corta, intenta de nuevo'); return; }
    const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
    await saveAudioNote(blob);

    const transcript = transcriptFinal.trim();
    if (transcript) {
      $('#transcriptTextInput').value = transcript;
      openModal('#transcriptModal');
    }
  };

  mediaRecorder.start();
  startTranscription();
  recordStartTime = Date.now();
  $('#qcRecordBtn').textContent = '⏹ Detener grabación';
  $('#qcRecordBtn').classList.add('recording');
  $('#qcRecordTimer').classList.remove('hidden');
  recordTimerInterval = setInterval(() => {
    const secs = Math.floor((Date.now() - recordStartTime) / 1000);
    $('#qcRecordTimer').textContent = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;
  }, 500);
}

$('#qcRecordBtn').addEventListener('click', toggleRecording);

async function saveAudioNote(blob) {
  const id = uid();
  const now = Date.now();
  const title = 'Nota de voz · ' + new Date(now).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });

  let payload;
  if (Crypto.sessionKey) {
    const buffer = await blob.arrayBuffer();
    const { iv, ciphertext } = await Crypto.encryptBuffer(buffer);
    payload = { encrypted: true, iv, ciphertext, mime: blob.type };
  } else {
    payload = { encrypted: false, blob, mime: blob.type };
  }

  try {
    await AudioDB.put(id, payload);
  } catch (e) {
    toast('No se pudo guardar el audio (¿poco espacio?)');
    return;
  }

  notes.push({ id, title, category: 'Audio', isAudio: true, content: '', createdAt: now, updatedAt: now });
  saveNotes();
  toast('Nota de voz guardada 🎙️');
  if ($('#view-notas').classList.contains('active')) renderNotesList();
}

/* ---- Modal de transcripcion ---- */
$('#closeTranscriptModal').addEventListener('click', () => closeModal('#transcriptModal'));

$('#transcriptAsTaskBtn').addEventListener('click', () => {
  const text = $('#transcriptTextInput').value.trim();
  if (!text) { toast('Escribe algo primero'); return; }
  tasks.push({ id: uid(), text, date: todayStr(), done: false, createdAt: Date.now(), doneAt: null });
  saveTasks();
  renderHoy(); renderTareas();
  closeModal('#transcriptModal');
  toast('Tarea creada desde el audio ✅');
});

$('#transcriptAsNoteBtn').addEventListener('click', async () => {
  const text = $('#transcriptTextInput').value.trim();
  if (!text) { toast('Escribe algo primero'); return; }
  const unlocked = await requireUnlock();
  if (!unlocked) return;
  const content = await Crypto.encryptText(text);
  notes.push({ id: uid(), title: text.slice(0, 40), category: 'General', content, createdAt: Date.now(), updatedAt: Date.now() });
  saveNotes();
  closeModal('#transcriptModal');
  if ($('#view-notas').classList.contains('active')) renderNotesList();
  toast('Nota creada desde el audio 🗒️');
});

/* ========================= INICIO ========================= */
function renderGreeting() {
  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Buenos días' : hour < 20 ? 'Buenas tardes' : 'Buenas noches';
  $('#greeting').textContent = greeting;
  $('#todayDate').textContent = new Date().toLocaleDateString('es-ES', { weekday: 'long', day: 'numeric', month: 'long' });
}

function init() {
  renderGreeting();
  renderHoy();
  renderTareas();
  renderStreak();

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
}

init();
