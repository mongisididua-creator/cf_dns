const CONFIG = window.CF_DNS_CONFIG || {};
const APPS_SCRIPT_URL = String(CONFIG.APPS_SCRIPT_URL || '').trim();

const SESSION_STORAGE_KEY = 'cfdns_admin_session_v1';
const CLIENT_STORAGE_KEY = 'cfdns_client_id_v1';
const ZONE_STORAGE_KEY = 'cfdns_last_zone_v1';

const state = {
  sessionToken: '',
  clientId: '',
  zones: [],
  activeZoneId: '',
  records: [],
  tunnels: [],
  tunnelDiagnostics: {
    total: 0,
    remote: 0,
    local: 0,
    error: ''
  },
  activeTunnelId: '',
  publishedApps: [],
  tunnelLoaded: false,
  editRecord: null,
  editPublished: null,
  deleteRecord: null,
  deletePublished: null,
  backendWarmStarted: false,
  rpcSeq: 0,
  rpcPending: new Map()
};

document.addEventListener('DOMContentLoaded', async () => {
  bindUI();

  state.sessionToken = safeStorageGet(sessionStorage, SESSION_STORAGE_KEY);
  state.clientId = getOrCreateClientId();

  try {
    validateBackendUrl();
    warmBackendSilently();
  } catch (err) {
    showAuth();
    showAuthError(err.message);
    return;
  }

  if (!state.sessionToken) {
    showAuth();
    return;
  }

  hideAuth();
  await initialize();
});

function bindUI() {
  document.getElementById('adminLoginForm').addEventListener('submit', loginAdmin);

  document.getElementById('togglePassword').addEventListener('click', () => {
    const input = document.getElementById('adminPasswordInput');
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  document.querySelectorAll('[data-view-link]').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.viewLink));
  });

  document.querySelectorAll('[data-open-record]').forEach(btn => {
    btn.addEventListener('click', () => openRecordModal());
  });

  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
  });

  document.querySelectorAll('.modal-backdrop').forEach(el => {
    el.addEventListener('click', e => {
      if (e.target === el) closeModal(el.id);
    });
  });

  document.getElementById('logoutBtn').addEventListener('click', logoutAdmin);
  document.getElementById('refreshBtn').addEventListener('click', refreshRecords);
  document.getElementById('testConnectionBtn').addEventListener('click', testConnection);
  document.getElementById('reloadTunnelBtn').addEventListener('click', () => ensureTunnelDataLoaded(true));
  document.getElementById('mobileMenu').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
  document.getElementById('tunnelSelect').addEventListener('change', async e => { await changeTunnel(e.target.value); });
  document.getElementById('addPublishedBtn').addEventListener('click', () => openPublishedModal());
  document.getElementById('publishedZoneSelect').addEventListener('change', syncPublishedZoneSuffix);
  document.getElementById('publishedForm').addEventListener('submit', savePublishedApp);

  document.getElementById('zoneSelect').addEventListener('change', async e => {
    await changeZone(e.target.value);
  });

  document.getElementById('recordSearch').addEventListener('input', renderRecordTable);
  document.getElementById('typeFilter').addEventListener('change', renderRecordTable);
  document.getElementById('recordType').addEventListener('change', updateRecordTypeUI);
  document.getElementById('recordProxied').addEventListener('change', syncTtlForProxy);
  document.getElementById('recordForm').addEventListener('submit', saveRecord);
  document.getElementById('confirmDeleteBtn').addEventListener('click', confirmDelete);
}

function safeStorageGet(storage, key) {
  try { return storage.getItem(key) || ''; } catch (_) { return ''; }
}
function safeStorageSet(storage, key, value) {
  try { storage.setItem(key, value); return true; } catch (_) { return false; }
}
function safeStorageRemove(storage, key) {
  try { storage.removeItem(key); } catch (_) {}
}

function makeNonce() {
  if (globalThis.crypto && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(24);
  if (globalThis.crypto && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  return `${Date.now()}_${Math.random().toString(36).slice(2)}_${Math.random().toString(36).slice(2)}`;
}

function getOrCreateClientId() {
  let id = safeStorageGet(localStorage, CLIENT_STORAGE_KEY);
  if (/^[A-Za-z0-9_-]{20,120}$/.test(id)) return id;

  id = makeNonce().replace(/[^A-Za-z0-9_-]/g, '').slice(0, 96);
  safeStorageSet(localStorage, CLIENT_STORAGE_KEY, id);
  return id;
}

function validateBackendUrl() {
  if (!APPS_SCRIPT_URL) {
    throw new Error('Isi APPS_SCRIPT_URL di config.js.');
  }

  let url;
  try { url = new URL(APPS_SCRIPT_URL); }
  catch (_) { throw new Error('APPS_SCRIPT_URL tidak valid.'); }

  if (
    url.protocol !== 'https:' ||
    url.hostname !== 'script.google.com' ||
    !/^\/macros\/s\/[^/]+\/exec\/?$/.test(url.pathname)
  ) {
    throw new Error('Gunakan URL deployment Apps Script yang berakhir /exec.');
  }
}

function warmBackendSilently() {
  if (state.backendWarmStarted || !APPS_SCRIPT_URL) return;
  state.backendWarmStarted = true;

  try {
    const url = new URL(APPS_SCRIPT_URL);
    url.searchParams.set('warm', String(Date.now()));
    fetch(url.toString(), {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      credentials: 'omit'
    }).catch(() => {});
  } catch (_) {}
}

function isAppsScriptResponseOrigin(origin) {
  try {
    const url = new URL(origin);
    return url.protocol === 'https:' && (
      url.hostname === 'script.google.com' ||
      url.hostname === 'script.googleusercontent.com' ||
      url.hostname.endsWith('.googleusercontent.com')
    );
  } catch (_) {
    return false;
  }
}

window.addEventListener('message', event => {
  const msg = event.data || {};
  if (msg.type !== 'cfdns-rpc-result' || !msg.id || !msg.nonce) return;

  const pending = state.rpcPending.get(msg.id);
  if (!pending || pending.nonce !== msg.nonce) return;

  const exactFrameSource = event.source === pending.iframe.contentWindow;
  const trustedOrigin =
    isAppsScriptResponseOrigin(event.origin) ||
    (event.origin === 'null' && exactFrameSource);

  if (!trustedOrigin) return;

  clearTimeout(pending.timer);
  pending.iframe.remove();
  state.rpcPending.delete(msg.id);

  if (msg.ok) {
    pending.resolve(msg.result);
    return;
  }

  const error = new Error(msg.error || 'Backend error.');
  if (/Sesi admin|Token sesi/i.test(error.message)) {
    clearAdminSession();
    showAuth();
  }
  pending.reject(error);
});

function gas(method, ...args) {
  return new Promise((resolve, reject) => {
    validateBackendUrl();

    const id = `rpc_${Date.now()}_${++state.rpcSeq}_${makeNonce().slice(0, 8)}`;
    const nonce = makeNonce();
    const frameName = `cfdns_rpc_${state.rpcSeq}_${Date.now()}`;

    const iframe = document.createElement('iframe');
    iframe.name = frameName;
    iframe.title = 'CF DNS RPC';
    iframe.setAttribute('aria-hidden', 'true');
    iframe.style.cssText = 'position:fixed;width:1px;height:1px;left:-9999px;top:-9999px;border:0;opacity:0;pointer-events:none;';
    document.body.appendChild(iframe);

    const form = document.createElement('form');
    form.method = 'POST';
    form.action = APPS_SCRIPT_URL;
    form.target = frameName;
    form.acceptCharset = 'UTF-8';
    form.style.display = 'none';

    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'payload';
    input.value = JSON.stringify({
      id,
      nonce,
      method,
      args,
      sessionToken: state.sessionToken || '',
      clientId: state.clientId || '',
      requestOrigin: window.location.origin || ''
    });

    form.appendChild(input);
    document.body.appendChild(form);

    const timeoutByMethod = {
      loginAdmin: 45000,
      getInitialData: 45000,
      getTunnelData: 60000,
      listPublishedApplications: 60000,
      createPublishedApplication: 60000,
      updatePublishedApplication: 60000,
      deletePublishedApplication: 60000
    };
    const timeoutMs = timeoutByMethod[method] || 30000;

    const timer = setTimeout(() => {
      if (!state.rpcPending.has(id)) return;
      state.rpcPending.delete(id);
      iframe.remove();

      const label = tunnelMethods.has(method)
        ? 'Cloudflare Tunnel API'
        : 'Backend Apps Script';

      reject(new Error(`${label} tidak merespons dalam ${Math.round(timeoutMs/1000)} detik.`));
    }, timeoutMs);

    state.rpcPending.set(id, {resolve, reject, nonce, iframe, timer});

    try {
      form.submit();
    } catch (err) {
      clearTimeout(timer);
      state.rpcPending.delete(id);
      iframe.remove();
      reject(err);
    } finally {
      form.remove();
    }
  });
}

async function loginAdmin(e) {
  e.preventDefault();

  const input = document.getElementById('adminPasswordInput');
  const button = document.getElementById('adminLoginBtn');

  if (!input.value || button.disabled) return;

  button.disabled = true;
  button.dataset.originalText = button.textContent;
  button.textContent = 'Memeriksa...';
  hideAuthError();
  showLoading('Memeriksa password...');

  try {
    const result = await gas('loginAdmin', input.value);
    saveAdminSession(result && result.sessionToken ? result.sessionToken : '');

    if (!state.sessionToken) {
      throw new Error('Backend tidak mengembalikan sesi login.');
    }

    input.value = '';
    hideAuth();
    showLoading('Memuat Cloudflare...');
    toast('Login berhasil.', 'success');
    await initialize();
  } catch (err) {
    input.focus();
    input.select();
    showAuthError(err.message || 'Login gagal.');
    toast(err.message || 'Login gagal.', 'error');
  } finally {
    hideLoading();
    button.disabled = false;
    button.textContent = button.dataset.originalText || 'Masuk sebagai Admin';
  }
}

async function logoutAdmin() {
  try { await gas('logoutAdmin'); } catch (_) {}
  clearAdminSession();
  state.zones = [];
  state.records = [];
  state.activeZoneId = '';
  showAuth();
  toast('Anda telah keluar.');
}

function saveAdminSession(token) {
  state.sessionToken = String(token || '');
  if (state.sessionToken) {
    safeStorageSet(sessionStorage, SESSION_STORAGE_KEY, state.sessionToken);
  } else {
    safeStorageRemove(sessionStorage, SESSION_STORAGE_KEY);
  }
}

function clearAdminSession() {
  state.sessionToken = '';
  safeStorageRemove(sessionStorage, SESSION_STORAGE_KEY);
}

async function initialize() {
  showLoading('Memuat DNS Cloudflare...');

  try {
    // Startup sengaja hanya mengambil Zone.
    // Tunnel API dimuat saat menu Published Applications dibuka.
    const initial = await gas('getInitialData');

    state.zones = Array.isArray(initial.zones) ? initial.zones : [];
    state.tunnels = [];
    state.publishedApps = [];
    state.tunnelLoaded = false;
    state.tunnelDiagnostics = {
      total:0,
      remote:0,
      local:0,
      error:''
    };

    renderConnectionStatus(initial.configured !== false);
    populateZones();
    populateTunnels();

    document.getElementById('accountStatus').textContent =
      initial.accountId ? 'Terdeteksi' : 'Belum tersedia';

    document.getElementById('tunnelPermissionStatus').textContent = 'Belum dimuat';

    const tunnelDiag = document.getElementById('tunnelDiagnostic');
    if (tunnelDiag) {
      tunnelDiag.textContent =
        'Tunnel tidak dimuat saat login agar dashboard DNS tetap cepat. ' +
        'Buka menu Published Applications untuk memuat Cloudflare Tunnel.';
      tunnelDiag.className = 'diagnostic';
    }

    if (!state.zones.length) {
      state.activeZoneId = '';
      state.records = [];
      renderAll();
      switchView('settings');
      toast('Tidak ada zone yang dapat diakses oleh token ini.', 'error');
      return;
    }

    const savedZone = safeStorageGet(localStorage, ZONE_STORAGE_KEY);
    const chosen = state.zones.some(z => z.id === savedZone)
      ? savedZone
      : state.zones[0].id;

    state.activeZoneId = chosen;
    document.getElementById('zoneSelect').value = chosen;
    document.getElementById('recordZoneSelect').value = chosen;
    safeStorageSet(localStorage, ZONE_STORAGE_KEY, chosen);

    await loadRecords();
    renderPublishedApps();
  } catch (err) {
    renderConnectionStatus(false);

    if (/Sesi admin|Token sesi/i.test(err.message)) {
      clearAdminSession();
      showAuth();
    }

    toast(err.message, 'error');
  } finally {
    hideLoading();
  }
}

async function changeZone(zoneId) {
  if (!zoneId || zoneId === state.activeZoneId) return;

  state.activeZoneId = zoneId;
  safeStorageSet(localStorage, ZONE_STORAGE_KEY, zoneId);
  document.getElementById('recordZoneSelect').value = zoneId;

  showLoading('Memuat DNS...');
  try {
    await loadRecords();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    hideLoading();
  }
}

async function loadRecords() {
  if (!state.activeZoneId) {
    state.records = [];
    renderAll();
    return;
  }

  const result = await gas('listDnsRecords', state.activeZoneId);
  state.records = Array.isArray(result) ? result : [];
  renderAll();
}

async function refreshRecords() {
  if (!state.activeZoneId) return;

  showLoading('Memperbarui DNS...');
  try {
    await loadRecords();
    toast('Data DNS diperbarui.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    hideLoading();
  }
}

async function ensureTunnelDataLoaded(force = false) {
  if (state.tunnelLoaded && !force) return;

  showLoading('Memuat Cloudflare Tunnel...');

  try {
    const result = await gas('getTunnelData');

    state.tunnels = Array.isArray(result.tunnels) ? result.tunnels : [];
    state.tunnelDiagnostics = {
      total:Number(result.summary?.total || 0),
      remote:Number(result.summary?.remote || 0),
      local:Number(result.summary?.local || 0),
      error:String(result.error || '')
    };
    state.tunnelLoaded = true;

    populateTunnels();
    renderTunnelDiagnostics(result);

    if (state.tunnels.length) {
      const stillExists = state.tunnels.some(t => t.id === state.activeTunnelId);
      if (!stillExists) {
        state.activeTunnelId = state.tunnels[0].id;
      }

      document.getElementById('tunnelSelect').value = state.activeTunnelId;
      document.getElementById('publishedTunnelSelect').value = state.activeTunnelId;

      await loadPublishedApps();
    } else {
      state.activeTunnelId = '';
      state.publishedApps = [];
      renderPublishedApps();
    }
  } catch (err) {
    state.tunnelLoaded = true;
    state.tunnels = [];
    state.publishedApps = [];
    state.tunnelDiagnostics.error = err.message || String(err);

    populateTunnels();
    renderTunnelDiagnostics({
      error:state.tunnelDiagnostics.error,
      summary:state.tunnelDiagnostics
    });
    renderPublishedApps();

    toast(err.message || 'Gagal memuat Cloudflare Tunnel.', 'error');
  } finally {
    hideLoading();
  }
}

function renderTunnelDiagnostics(result) {
  const error = String(result?.error || '');
  const summary = result?.summary || {total:0,remote:0,local:0};

  document.getElementById('tunnelPermissionStatus').textContent = error
    ? 'Gagal membaca tunnel'
    : (Number(summary.remote || 0)
        ? `Siap — ${Number(summary.remote || 0)} remote-managed`
        : (Number(summary.local || 0)
            ? `${Number(summary.local || 0)} tunnel lokal`
            : 'Siap — tidak ada tunnel'));

  const el = document.getElementById('tunnelDiagnostic');
  if (!el) return;

  if (error) {
    el.textContent = error;
    el.className = 'diagnostic error';
  } else if (Number(summary.local || 0) && !Number(summary.remote || 0)) {
    el.textContent =
      `${Number(summary.local || 0)} tunnel ditemukan sebagai locally-managed. ` +
      'Published Applications melalui API memerlukan remote-managed tunnel.';
    el.className = 'diagnostic warn';
  } else if (!Number(summary.total || 0)) {
    el.textContent =
      'API Tunnel berhasil diakses, tetapi tidak ada Cloudflare Tunnel pada account ini.';
    el.className = 'diagnostic warn';
  } else {
    el.textContent =
      `${Number(summary.total || 0)} tunnel terdeteksi; ` +
      `${Number(summary.remote || 0)} remote-managed dapat dikelola.`;
    el.className = 'diagnostic good';
  }
}

function populateTunnels() {
  const select = document.getElementById('tunnelSelect');
  const modalSelect = document.getElementById('publishedTunnelSelect');
  let emptyText = 'Tidak ada remote-managed tunnel';

  if (state.tunnelDiagnostics.error) {
    emptyText = 'Tunnel gagal dibaca — lihat Pengaturan';
  } else if (state.tunnelDiagnostics.local > 0) {
    emptyText = `${state.tunnelDiagnostics.local} tunnel lokal — tidak dapat diedit`;
  }

  const html = state.tunnels.length
    ? state.tunnels.map(t => `<option value="${escAttr(t.id)}">${esc(t.name)}${t.status ? ` — ${esc(t.status)}` : ''}</option>`).join('')
    : `<option value="">${esc(emptyText)}</option>`;
  select.innerHTML = html;
  modalSelect.innerHTML = html;
  document.getElementById('statTunnels').textContent = state.tunnels.length;
}

async function changeTunnel(tunnelId) {
  if (!tunnelId || tunnelId === state.activeTunnelId) return;
  state.activeTunnelId = tunnelId;
  document.getElementById('publishedTunnelSelect').value = tunnelId;
  showLoading('Memuat Published Applications...');
  try { await loadPublishedApps(); } catch (err) { toast(err.message,'error'); } finally { hideLoading(); }
}

async function loadPublishedApps() {
  if (!state.activeTunnelId) { state.publishedApps=[]; renderPublishedApps(); return; }
  const result = await gas('listPublishedApplications', state.activeTunnelId);
  state.publishedApps = Array.isArray(result) ? result : [];
  renderPublishedApps();
}

function renderPublishedApps() {
  const body=document.getElementById('publishedTableBody');
  const tunnel=state.tunnels.find(t=>t.id===state.activeTunnelId)||null;
  document.getElementById('publishedCount').textContent=state.publishedApps.length;
  document.getElementById('statPublished').textContent=state.publishedApps.length;
  document.getElementById('activeTunnelStatus').textContent=tunnel?(tunnel.status||'unknown'):'—';
  if(!tunnel){body.innerHTML='<tr><td colspan="5" class="center">Tidak ada tunnel yang dapat dikelola.</td></tr>';return;}
  if(!state.publishedApps.length){body.innerHTML='<tr><td colspan="5" class="center">Belum ada Published Application pada tunnel ini.</td></tr>';return;}
  body.innerHTML=state.publishedApps.map(route=>`<tr><td><div class="table-name"><strong>${esc(route.hostname)}</strong><span>${esc(tunnel.name)}</span></div></td><td>${esc(route.service)}</td><td>${esc(route.path||'—')}</td><td><span class="dns-ok">DNS Otomatis</span></td><td><div class="row-actions"><button class="table-btn" data-open-host="${escAttr(route.hostname)}">Buka</button><button class="table-btn" data-edit-published="${route.index}">Edit</button><button class="table-btn danger" data-delete-published="${route.index}">Hapus</button></div></td></tr>`).join('');
  body.querySelectorAll('[data-open-host]').forEach(btn=>btn.addEventListener('click',()=>window.open('https://'+btn.dataset.openHost,'_blank','noopener')));
  body.querySelectorAll('[data-edit-published]').forEach(btn=>btn.addEventListener('click',()=>editPublishedApp(Number(btn.dataset.editPublished))));
  body.querySelectorAll('[data-delete-published]').forEach(btn=>btn.addEventListener('click',()=>askDeletePublished(Number(btn.dataset.deletePublished))));
}

function openPublishedModal(route=null){
  if(!state.activeTunnelId){toast('Tidak ada tunnel yang dapat dikelola.','error');return;}
  if(!state.zones.length){toast('Tidak ada zone Cloudflare.','error');return;}
  state.editPublished=route?{...route}:null;
  document.getElementById('publishedModalBadge').textContent=route?'EDIT PUBLISHED APPLICATION':'PUBLISHED APPLICATION';
  document.getElementById('publishedModalTitle').textContent=route?'Edit Published Application':'Tambah Published Application';
  document.getElementById('publishedTunnelSelect').value=state.activeTunnelId;
  const zoneSelect=document.getElementById('publishedZoneSelect');
  zoneSelect.innerHTML=state.zones.map(z=>`<option value="${escAttr(z.id)}">${esc(z.name)}</option>`).join('');
  let zone=activeZone(), hostValue='';
  if(route){const found=state.zones.find(z=>route.hostname===z.name||route.hostname.endsWith('.'+z.name));if(found)zone=found;if(zone)hostValue=hostFromName(route.hostname,zone.name);}
  if(!zone)zone=state.zones[0];
  zoneSelect.value=zone.id;
  document.getElementById('publishedHost').value=route?hostValue:'';
  document.getElementById('publishedService').value=route?route.service:'';
  document.getElementById('publishedPath').value=route?(route.path||''):'';
  syncPublishedZoneSuffix();openModal('publishedModal');
}
function syncPublishedZoneSuffix(){const zone=state.zones.find(z=>z.id===document.getElementById('publishedZoneSelect').value);document.getElementById('publishedZoneSuffix').textContent=zone?'.'+zone.name:'';}
function editPublishedApp(index){const route=state.publishedApps.find(r=>r.index===index);if(route)openPublishedModal(route);}
async function savePublishedApp(e){
  e.preventDefault(); const tunnelId=state.activeTunnelId, zoneId=document.getElementById('publishedZoneSelect').value, host=document.getElementById('publishedHost').value.trim(), service=document.getElementById('publishedService').value.trim(), path=document.getElementById('publishedPath').value.trim();
  if(!host||!service){toast('Hostname dan Service URL wajib diisi.','error');return;}
  const payload={zoneId,host,service,path}; showLoading(state.editPublished?'Memperbarui route...':'Membuat route...');
  try{if(state.editPublished){payload.expectedHostname = state.editPublished.hostname || '';
      payload.expectedPath = state.editPublished.path || '';
      await gas('updatePublishedApplication',tunnelId,state.editPublished.index,payload);toast('Published Application berhasil diperbarui.','success');}else{await gas('createPublishedApplication',tunnelId,payload);toast('Published Application berhasil dibuat.','success');}state.editPublished=null;closeModal('publishedModal');await loadPublishedApps();await loadRecords();}catch(err){toast(err.message,'error');}finally{hideLoading();}
}
function askDeletePublished(index){const route=state.publishedApps.find(r=>r.index===index);if(!route)return;state.deletePublished=route;state.deleteRecord=null;document.getElementById('deleteTitle').textContent='Hapus Published Application?';document.getElementById('deleteMessage').innerHTML=`Route <b>${esc(route.hostname)}</b> akan dihapus. CNAME yang memang menunjuk ke tunnel ini juga akan dibersihkan.`;openModal('deleteModal');}

function populateZones() {
  const zoneSelect = document.getElementById('zoneSelect');
  const recordZoneSelect = document.getElementById('recordZoneSelect');

  const html = state.zones.length
    ? state.zones.map(z => `<option value="${escAttr(z.id)}">${esc(z.name)}</option>`).join('')
    : '<option value="">Tidak ada zone</option>';

  zoneSelect.innerHTML = html;
  recordZoneSelect.innerHTML = html;

  document.getElementById('statZones').textContent = state.zones.length;
  document.getElementById('zoneCountSetting').textContent = state.zones.length || '—';
}

function renderAll() {
  renderDashboardStats();
  renderRecentRecords();
  renderRecordTable();
  renderSettings();

  const zone = activeZone();
  const zoneName = zone ? zone.name : 'Belum ada zone';

  document.getElementById('recentZoneLabel').textContent = zone ? `Zone: ${zone.name}` : 'Belum ada zone dipilih.';
  document.getElementById('profileZone').textContent = zoneName;
  document.getElementById('activeZoneSetting').textContent = zoneName;
}

function renderDashboardStats() {
  document.getElementById('statRecords').textContent = state.records.length;
  document.getElementById('statTunnels').textContent = state.tunnels.length;
  document.getElementById('statPublished').textContent = state.publishedApps.length;
}

function renderRecentRecords() {
  const wrap = document.getElementById('recentRecords');
  const rows = state.records.slice(0, 6);

  if (!rows.length) {
    wrap.innerHTML = '<div class="center">Belum ada DNS record pada zone ini.</div>';
    return;
  }

  wrap.innerHTML = rows.map(r => `
    <div class="repo-row">
      <div class="repo-icon ${typeClass(r.type)}">${esc(r.type)}</div>
      <div class="repo-main">
        <strong>${esc(r.name)}</strong>
        <p>${esc(r.content || '')}</p>
      </div>
      <div class="repo-meta">
        <span class="pill">${r.ttl === 1 ? 'TTL Auto' : `TTL ${esc(r.ttl)}`}</span>
        <span class="pill ${r.proxied ? 'orange' : ''}">${r.proxied ? 'Proxied' : 'DNS Only'}</span>
      </div>
      <button class="small-btn" data-edit-record="${escAttr(r.id)}">Kelola</button>
    </div>
  `).join('');

  wrap.querySelectorAll('[data-edit-record]').forEach(btn => {
    btn.addEventListener('click', () => editRecord(btn.dataset.editRecord));
  });
}

function filteredRecords() {
  const q = document.getElementById('recordSearch').value.trim().toLowerCase();
  const type = document.getElementById('typeFilter').value;

  return state.records.filter(r => {
    if (type && r.type !== type) return false;
    if (!q) return true;

    return (
      String(r.name || '').toLowerCase().includes(q) ||
      String(r.content || '').toLowerCase().includes(q) ||
      String(r.type || '').toLowerCase().includes(q)
    );
  });
}

function renderRecordTable() {
  const body = document.getElementById('recordTableBody');
  const rows = filteredRecords();

  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="center">Tidak ada DNS record yang cocok.</td></tr>';
    return;
  }

  body.innerHTML = rows.map(r => `
    <tr>
      <td>
        <div class="table-name">
          <strong>${esc(r.name)}</strong>
          <span>${esc(shortHost(r.name))}</span>
        </div>
      </td>
      <td><span class="type-badge ${typeClass(r.type)}">${esc(r.type)}</span></td>
      <td>${esc(r.content)}</td>
      <td>${r.ttl === 1 ? 'Auto' : esc(r.ttl)}</td>
      <td><span class="pill ${r.proxied ? 'orange' : ''}">${r.proxied ? 'Proxied' : 'DNS Only'}</span></td>
      <td>
        <div class="row-actions">
          <button class="table-btn" data-copy="${escAttr(r.name)}">Salin</button>
          <button class="table-btn" data-edit="${escAttr(r.id)}">Edit</button>
          <button class="table-btn danger" data-delete="${escAttr(r.id)}">Hapus</button>
        </div>
      </td>
    </tr>
  `).join('');

  body.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => copyText(btn.dataset.copy));
  });

  body.querySelectorAll('[data-edit]').forEach(btn => {
    btn.addEventListener('click', () => editRecord(btn.dataset.edit));
  });

  body.querySelectorAll('[data-delete]').forEach(btn => {
    btn.addEventListener('click', () => askDeleteRecord(btn.dataset.delete));
  });
}

function openRecordModal(record = null) {
  const zone = activeZone();
  if (!zone) {
    toast('Pilih zone terlebih dahulu.', 'error');
    return;
  }

  state.editRecord = record ? {...record} : null;

  document.getElementById('recordModalBadge').textContent = record ? 'EDIT DNS RECORD' : 'DNS RECORD BARU';
  document.getElementById('recordModalTitle').textContent = record ? 'Edit DNS Record' : 'Tambah DNS Record';

  document.getElementById('recordZoneSelect').value = state.activeZoneId;
  document.getElementById('hostSuffix').textContent = '.' + zone.name;
  document.getElementById('recordHost').value = record ? hostFromName(record.name, zone.name) : '';
  document.getElementById('recordType').value = record ? record.type : 'A';
  document.getElementById('recordTarget').value = record ? record.content : '';

  const supportedTtl = [1,60,120,300,3600];
  const ttlValue = record && supportedTtl.includes(Number(record.ttl)) ? Number(record.ttl) : 1;
  document.getElementById('recordTtl').value = String(ttlValue);
  document.getElementById('recordProxied').checked = record ? Boolean(record.proxied) : true;

  updateRecordTypeUI();
  syncTtlForProxy();
  openModal('recordModal');
}

function editRecord(id) {
  const record = state.records.find(r => r.id === id);
  if (record) openRecordModal(record);
}

function updateRecordTypeUI() {
  const type = document.getElementById('recordType').value;
  const label = document.getElementById('targetLabel');
  const target = document.getElementById('recordTarget');

  if (type === 'A') {
    label.textContent = 'Target IPv4';
    target.placeholder = '192.0.2.10';
  } else if (type === 'AAAA') {
    label.textContent = 'Target IPv6';
    target.placeholder = '2001:db8::1';
  } else {
    label.textContent = 'Target CNAME';
    target.placeholder = 'target.domainanda.id';
  }
}

function syncTtlForProxy() {
  const proxied = document.getElementById('recordProxied').checked;
  const ttl = document.getElementById('recordTtl');

  if (proxied) {
    ttl.value = '1';
    ttl.disabled = true;
  } else {
    ttl.disabled = false;
  }
}

async function saveRecord(e) {
  e.preventDefault();

  const host = document.getElementById('recordHost').value.trim();
  const type = document.getElementById('recordType').value;
  const content = document.getElementById('recordTarget').value.trim();
  const proxied = document.getElementById('recordProxied').checked;
  const ttl = Number(document.getElementById('recordTtl').value || 1);

  if (!host || !content) {
    toast('Nama DNS dan target wajib diisi.', 'error');
    return;
  }

  const payload = {host, type, content, proxied, ttl};

  showLoading(state.editRecord ? 'Memperbarui DNS...' : 'Membuat DNS...');

  try {
    if (state.editRecord) {
      await gas('updateDnsRecord', state.activeZoneId, state.editRecord.id, payload);
      toast('DNS record berhasil diperbarui.', 'success');
    } else {
      await gas('createDnsRecord', state.activeZoneId, payload);
      toast('DNS record berhasil dibuat.', 'success');
    }

    state.editRecord = null;
    closeModal('recordModal');
    await loadRecords();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    hideLoading();
  }
}

function askDeleteRecord(id) {
  const record = state.records.find(r => r.id === id);
  if (!record) return;

  state.deleteRecord = record;
  state.deletePublished = null;
  document.getElementById('deleteTitle').textContent = 'Hapus DNS Record?';
  document.getElementById('deleteMessage').innerHTML =
    `DNS <b>${esc(record.name)}</b> akan dihapus permanen dari Cloudflare.`;

  openModal('deleteModal');
}

async function confirmDelete() {
  if (state.deletePublished) {
    const route=state.deletePublished; closeModal('deleteModal'); showLoading('Menghapus Published Application...');
    try { await gas(
        'deletePublishedApplication',
        state.activeTunnelId,
        route.index,
        route.hostname || '',
        route.path || ''
      ); state.deletePublished=null; toast('Published Application berhasil dihapus.','success'); await loadPublishedApps(); await loadRecords(); }
    catch(err){toast(err.message,'error');} finally {hideLoading();}
    return;
  }
  if (!state.deleteRecord) return;
  const record=state.deleteRecord; closeModal('deleteModal'); showLoading('Menghapus DNS...');
  try { await gas('deleteDnsRecord',state.activeZoneId,record.id); state.deleteRecord=null; toast('DNS record berhasil dihapus.','success'); await loadRecords(); }
  catch(err){toast(err.message,'error');} finally {hideLoading();}
}

async function testConnection() {
  showLoading('Menguji DNS Cloudflare...');

  try {
    const result = await gas('testCloudflareConnection');
    renderConnectionStatus(true);

    document.getElementById('accountStatus').textContent =
      result.accountId ? 'Terdeteksi' : 'Belum tersedia';

    toast(`DNS Cloudflare terhubung. ${result.zoneCount} zone tersedia.`, 'success');
  } catch (err) {
    renderConnectionStatus(false);
    toast(err.message, 'error');
  } finally {
    hideLoading();
  }
}

function renderConnectionStatus(ok) {
  const pill = document.getElementById('connectionPill');
  pill.textContent = ok ? 'Terhubung' : 'Bermasalah';
  pill.className = 'status ' + (ok ? 'good' : 'bad');
  document.getElementById('tokenStatus').textContent = ok ? 'Siap' : 'Periksa konfigurasi';
}

function renderSettings() {
  document.getElementById('zoneCountSetting').textContent = state.zones.length || '—';
  document.getElementById('activeZoneSetting').textContent = activeZone()?.name || '—';
}

function activeZone() {
  return state.zones.find(z => z.id === state.activeZoneId) || null;
}

function hostFromName(name, zoneName) {
  if (name === zoneName) return '@';
  const suffix = '.' + zoneName;
  return name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
}

function shortHost(name) {
  const zone = activeZone();
  return zone ? hostFromName(name, zone.name) : name;
}

function switchView(view) {
  const labels = {
    dashboard:['Dashboard','Kelola DNS Cloudflare.'],
    records:['DNS Records','Tambah, edit, dan hapus DNS record.'],
    published:['Published Applications','Kelola public hostname dan service Cloudflare Tunnel.'],
    settings:['Pengaturan','Status koneksi dan konfigurasi aplikasi.']
  };

  const target = document.getElementById('view-' + view);
  if (!target || !labels[view]) {
    toast('Menu tidak ditemukan.', 'error');
    return;
  }

  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  target.classList.add('active');

  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.view === view);
  });

  document.getElementById('pageTitle').textContent = labels[view][0];
  document.getElementById('pageSubtitle').textContent = labels[view][1];
  document.getElementById('sidebar').classList.remove('open');

  if (view === 'published') {
    ensureTunnelDataLoaded(false);
  }
}

function showAuth() {
  document.getElementById('authScreen').classList.remove('hidden');
  document.getElementById('app').classList.add('app-locked');
  const input = document.getElementById('adminPasswordInput');
  if (input) {
    input.value = '';
    input.type = 'password';
  }
}

function hideAuth() {
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('app').classList.remove('app-locked');
  hideAuthError();
}

function showAuthError(message) {
  const el = document.getElementById('authNote');
  el.textContent = message || '';
}

function hideAuthError() {
  const el = document.getElementById('authNote');
  el.textContent = '';
}

function openModal(id) {
  document.getElementById(id).classList.add('show');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('show');
}

function showLoading(text) {
  document.getElementById('loadingText').textContent = text || 'Memproses...';
  document.getElementById('loadingOverlay').classList.add('show');
}

function hideLoading() {
  document.getElementById('loadingOverlay').classList.remove('show');
}

function toast(message, type = '') {
  const stack = document.getElementById('toastStack');
  const el = document.createElement('div');

  el.className = 'toast ' + type;
  el.textContent = message;

  stack.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const temp = document.createElement('textarea');
      temp.value = text;
      temp.style.position = 'fixed';
      temp.style.left = '-9999px';
      document.body.appendChild(temp);
      temp.select();
      document.execCommand('copy');
      temp.remove();
    }

    toast('Nama DNS berhasil disalin.', 'success');
  } catch (_) {
    toast('Gagal menyalin.', 'error');
  }
}

function typeClass(type) {
  const t = String(type || '').toLowerCase();
  if (t === 'cname') return 'cname';
  if (t === 'aaaa') return 'aaaa';
  return 'a';
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}

function escAttr(value) {
  return esc(value);
}
