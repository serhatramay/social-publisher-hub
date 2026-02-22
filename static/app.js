const providerListEl = document.getElementById('provider-list');
const providerSelectEl = document.getElementById('provider-select');
const providerConfigEl = document.getElementById('provider-config');
const providerFormFieldsEl = document.getElementById('provider-form-fields');
const providerConnectPanelEl = document.getElementById('provider-connect-panel');
const logsEl = document.getElementById('logs');
const publishChecksEl = document.getElementById('publish-checks');
const urlInputEl = document.getElementById('url');

let providers = [];
let providerTemplates = {};
let pendingFacebookState = null;
let urlMetaFetchTimer = null;
let lastMetaFetchUrl = '';

const DEFAULT_SELECTED_PROVIDERS = ['bluesky', 'mastodon'];
const SELECTED_PROVIDERS_STORAGE_KEY = 'social_publisher_selected_providers_v1';

const providerFieldSchemas = {
  bluesky: [
    { key: 'identifier', label: 'Email veya Handle', placeholder: 'ornek@site.com veya kullanici.bsky.social' },
    { key: 'app_password', label: 'App Password', placeholder: 'xxxx-xxxx-xxxx-xxxx', type: 'password' },
  ],
  mastodon: [
    { key: 'instance', label: 'Mastodon Instance', placeholder: 'https://mastodon.social' },
    { key: 'access_token', label: 'Access Token', placeholder: 'Mastodon access token', type: 'password' },
  ],
  facebook: [
    { key: 'page_id', label: 'Facebook Page ID', placeholder: '1234567890' },
    { key: 'page_access_token', label: 'Page Access Token', placeholder: 'EAAB...', type: 'password' },
  ],
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `HTTP ${res.status}`);
  }
  return res.json();
}

function hasGuidedForm(providerKey) {
  return Array.isArray(providerFieldSchemas[providerKey]);
}

function getSelectedProviderKey() {
  return providerSelectEl.value;
}

function getSavedSelectedProviders() {
  try {
    const raw = localStorage.getItem(SELECTED_PROVIDERS_STORAGE_KEY);
    if (!raw) return [...DEFAULT_SELECTED_PROVIDERS];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [...DEFAULT_SELECTED_PROVIDERS];
    return parsed;
  } catch (_) {
    return [...DEFAULT_SELECTED_PROVIDERS];
  }
}

function saveSelectedProviders(keys) {
  try {
    localStorage.setItem(SELECTED_PROVIDERS_STORAGE_KEY, JSON.stringify(keys));
  } catch (_) {
    // ignore localStorage failures
  }
}

function setSearchParamsWithoutReload(params) {
  const url = new URL(window.location.href);
  Object.entries(params).forEach(([key, val]) => {
    if (val === null || val === undefined || val === '') url.searchParams.delete(key);
    else url.searchParams.set(key, val);
  });
  window.history.replaceState({}, '', url.toString());
}

function renderProviderConfigFields(providerKey, values = {}) {
  providerFormFieldsEl.innerHTML = '';
  const schema = providerFieldSchemas[providerKey];

  if (!schema) {
    const info = document.createElement('div');
    info.className = 'provider-form-help';
    info.textContent = 'Bu provider için henüz sade form yok. Gelişmiş (JSON config) alanını kullan.';
    providerFormFieldsEl.appendChild(info);
    return;
  }

  const help = document.createElement('div');
  help.className = 'provider-form-help';
  help.textContent = 'Alanları doldur, Config Kaydet de, sonra Bağlantıyı Test Et.';
  providerFormFieldsEl.appendChild(help);

  schema.forEach((field) => {
    const label = document.createElement('label');
    label.textContent = field.label;
    const input = document.createElement('input');
    input.type = field.type || 'text';
    input.placeholder = field.placeholder || '';
    input.value = values[field.key] || '';
    input.dataset.configKey = field.key;
    input.autocomplete = 'off';
    providerFormFieldsEl.appendChild(label);
    providerFormFieldsEl.appendChild(input);
  });
}

function renderProviderConnectPanel(providerKey, providerConfig = {}) {
  providerConnectPanelEl.innerHTML = '';
  if (providerKey !== 'facebook') return;

  const status = document.createElement('div');
  status.className = 'provider-connect-status';
  status.textContent = providerConfig.page_name
    ? `Bağlı sayfa: ${providerConfig.page_name} (${providerConfig.page_id || ''})`
    : 'Kolay yöntem (opsiyonel): "Facebook ile Bağlan" ile page ve token otomatik alınır.';
  providerConnectPanelEl.appendChild(status);

  const actions = document.createElement('div');
  actions.className = 'provider-connect-actions';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'Facebook ile Bağlan';
  btn.addEventListener('click', async () => {
    try {
      const res = await api('/api/facebook/connect-url');
      if (!res.url) {
        alert(`Facebook connect hazır değil: ${JSON.stringify(res)}`);
        return;
      }
      window.location.href = res.url;
    } catch (err) {
      alert(`Facebook connect hatası: ${err.message}`);
    }
  });
  actions.appendChild(btn);
  providerConnectPanelEl.appendChild(actions);
}

function renderFacebookPagePicker(state, pages = []) {
  const wrap = document.createElement('div');
  wrap.className = 'page-picker';
  wrap.innerHTML = '<div class="provider-form-help">Facebook sayfanı seç (token otomatik kaydedilir):</div>';

  if (!pages.length) {
    const empty = document.createElement('div');
    empty.className = 'provider-form-help';
    empty.textContent = 'Sayfa bulunamadı. Yönetici olduğun bir page hesabı seçilmiş olmalı.';
    wrap.appendChild(empty);
  }

  pages.forEach((p) => {
    const row = document.createElement('div');
    row.className = 'page-picker-row';
    const title = document.createElement('div');
    title.textContent = `${p.name} (${p.id})`;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Seç';
    btn.addEventListener('click', async () => {
      try {
        await api('/api/facebook/select-page', {
          method: 'POST',
          body: JSON.stringify({ state, page_id: p.id }),
        });
        alert(`Facebook Page bağlandı: ${p.name}`);
        pendingFacebookState = null;
        setSearchParamsWithoutReload({ fb_connect_state: null, fb_connect_status: null, provider: 'facebook' });
        providerSelectEl.value = 'facebook';
        await loadProviders();
      } catch (err) {
        alert(`Facebook sayfa seçme hatası: ${err.message}`);
      }
    });
    row.appendChild(title);
    row.appendChild(btn);
    wrap.appendChild(row);
  });

  providerConnectPanelEl.appendChild(wrap);
}

function collectGuidedConfig(providerKey) {
  if (!hasGuidedForm(providerKey)) return null;
  const config = {};
  const inputs = providerFormFieldsEl.querySelectorAll('input[data-config-key]');
  inputs.forEach((input) => {
    config[input.dataset.configKey] = input.value.trim();
  });
  return config;
}

function validateGuidedConfig(providerKey, config) {
  if (!hasGuidedForm(providerKey)) return { ok: true, missing: [] };
  const missing = [];
  providerFieldSchemas[providerKey].forEach((field) => {
    if (!String(config[field.key] || '').trim()) missing.push(field.label);
  });
  return { ok: missing.length === 0, missing };
}

async function loadProviderConfigIntoEditor(providerKey) {
  try {
    const [templateResp, configResp] = await Promise.all([
      api(`/api/provider-config-template?provider=${encodeURIComponent(providerKey)}`),
      api(`/api/provider-config?provider=${encodeURIComponent(providerKey)}`),
    ]);
    const template = templateResp.template || {};
    const current = configResp.config || {};
    providerTemplates[providerKey] = template;
    const merged = { ...template, ...current };
    renderProviderConfigFields(providerKey, merged);
    renderProviderConnectPanel(providerKey, merged);
    providerConfigEl.value = JSON.stringify(merged, null, 2);
  } catch (err) {
    renderProviderConfigFields(providerKey, {});
    renderProviderConnectPanel(providerKey, {});
    providerConfigEl.value = '{}';
    alert(`Config yükleme hatası: ${err.message}`);
  }
}

function renderProviders() {
  providerListEl.innerHTML = '';
  providerSelectEl.innerHTML = '';
  const selectedSet = new Set(getSavedSelectedProviders());

  providers.forEach((p) => {
    const wrapper = document.createElement('div');
    wrapper.className = `provider-item ${p.mode} ${p.status} phase-${p.phase}`;

    const id = `provider-${p.key}`;
    wrapper.innerHTML = `
      <label>
        <input type="checkbox" id="${id}" value="${p.key}" ${selectedSet.has(p.key) ? 'checked' : ''} />
        ${p.label}
      </label>
      <div class="provider-meta">
        <span class="badge phase">P${p.phase}</span>
        <span class="badge ${p.status}">${p.status}</span>
      </div>
      <div class="provider-meta">
        mode: ${p.mode} | configured: ${p.configured ? 'yes' : 'no'} | ready: ${p.runtime_ready ? 'yes' : 'no'}
      </div>
      ${p.missing_config && p.missing_config.length ? `<div class="provider-meta">Eksik: ${p.missing_config.join(', ')}</div>` : ''}
      <div class="provider-meta">${p.notes || ''}</div>
    `;

    providerListEl.appendChild(wrapper);

    const opt = document.createElement('option');
    opt.value = p.key;
    opt.textContent = `${p.label} (${p.key})`;
    providerSelectEl.appendChild(opt);
  });

  if (providerSelectEl.options.length && !providerSelectEl.value) {
    providerSelectEl.selectedIndex = 0;
  }
}

function selectedProviders() {
  return Array.from(providerListEl.querySelectorAll('input[type="checkbox"]:checked')).map((x) => x.value);
}

function publishPayloadFromForm() {
  return {
    title: document.getElementById('title').value.trim(),
    url: document.getElementById('url').value.trim(),
    text_body: document.getElementById('text_body').value.trim(),
    image_url: document.getElementById('image_url').value.trim(),
    providers: selectedProviders(),
  };
}

async function fetchUrlMetaAndFill(force = false) {
  const url = urlInputEl.value.trim();
  if (!url) {
    alert('Önce URL gir.');
    return;
  }
  try {
    lastMetaFetchUrl = url;
    const data = await api(`/api/url-meta?url=${encodeURIComponent(url)}`);
    if (!data.ok) {
      alert('URL metadata alınamadı.');
      return;
    }
    const titleEl = document.getElementById('title');
    const textEl = document.getElementById('text_body');
    const imageEl = document.getElementById('image_url');

    if (data.canonical_url) {
      urlInputEl.value = data.canonical_url;
    }
    if (force || !titleEl.value.trim()) {
      titleEl.value = data.title || titleEl.value;
    }
    if (force || !textEl.value.trim()) {
      textEl.value = data.description || textEl.value;
    }
    if (force || !imageEl.value.trim()) {
      imageEl.value = data.image_url || imageEl.value;
    }
  } catch (err) {
    alert(`URL metadata hatası: ${err.message}`);
  }
}

function scheduleAutoUrlMetaFetch() {
  const url = urlInputEl.value.trim();
  if (!url || !/^https?:\/\//i.test(url)) return;
  if (url === lastMetaFetchUrl) return;
  clearTimeout(urlMetaFetchTimer);
  urlMetaFetchTimer = setTimeout(async () => {
    await fetchUrlMetaAndFill(false);
  }, 700);
}

function renderPublishChecks(items) {
  publishChecksEl.innerHTML = '';
  if (!items || !items.length) return;
  items.forEach((it) => {
    const ok = it.config_ok && it.post_ok;
    const div = document.createElement('div');
    div.className = `check-item ${ok ? 'ready' : 'blocked'}`;
    div.innerHTML = `
      <strong>${it.provider_key}</strong> - ${ok ? 'hazır' : 'hazır değil'} (P${it.phase || '?'}, ${it.status || 'unknown'})
      ${it.missing_config?.length ? `<div>Eksik config: ${it.missing_config.join(', ')}</div>` : ''}
      ${it.post_issues?.length ? `<div>İçerik sorunu: ${it.post_issues.join(', ')}</div>` : ''}
    `;
    publishChecksEl.appendChild(div);
  });
}

function renderLogs(items) {
  logsEl.innerHTML = '';
  if (!items.length) {
    logsEl.textContent = 'Henüz gönderim yok.';
    return;
  }

  items.forEach((item) => {
    const div = document.createElement('div');
    div.className = 'log-item';
    div.innerHTML = `
      <div><strong>${item.provider_key}</strong> - <span class="${item.status}">${item.status}</span></div>
      <div>${item.title}</div>
      <div>${item.url}</div>
      <div><small>${new Date(item.created_at).toLocaleString()}</small></div>
    `;
    logsEl.appendChild(div);
  });
}

async function loadProviders() {
  const data = await api('/api/providers');
  providers = data.items || [];
  renderProviders();
  if (providerSelectEl.value) {
    await loadProviderConfigIntoEditor(providerSelectEl.value);
  }
}

async function loadLogs() {
  const data = await api('/api/deliveries');
  renderLogs(data.items || []);
}

document.getElementById('publish-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = publishPayloadFromForm();
  const submitBtn = e.target.querySelector('button[type="submit"]');

  try {
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Paylaşılıyor...';
    }
    const precheck = await api('/api/publish-validate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    renderPublishChecks(precheck.items || []);
    const blocked = (precheck.items || []).filter((x) => !x.config_ok || !x.post_ok);
    if (blocked.length) {
      alert(`Paylaşım durduruldu. ${blocked.length} provider hazır değil.`);
      return;
    }

    const result = await api('/api/publish', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const okItems = (result.results || []).filter((x) => x.status === 'ok').map((x) => x.provider_key);
    const failItems = (result.results || []).filter((x) => x.status !== 'ok').map((x) => x.provider_key);
    const parts = [`Post ID: ${result.post_id}`];
    if (okItems.length) parts.push(`Başarılı: ${okItems.join(', ')}`);
    if (failItems.length) parts.push(`Başarısız: ${failItems.join(', ')}`);
    alert(`Gönderim tamamlandı.\n${parts.join('\n')}`);
    await loadProviders();
    await loadLogs();
  } catch (err) {
    alert(`Hata: ${err.message}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Paylaşımı Başlat';
    }
  }
});

document.getElementById('fetch-url-meta').addEventListener('click', async () => {
  await fetchUrlMetaAndFill(true);
});

document.getElementById('load-template').addEventListener('click', async () => {
  const provider = getSelectedProviderKey();
  try {
    const data = await api(`/api/provider-config-template?provider=${encodeURIComponent(provider)}`);
    providerConfigEl.value = JSON.stringify(data.template || {}, null, 2);
    renderProviderConfigFields(provider, data.template || {});
  } catch (err) {
    alert(`Template alınamadı: ${err.message}`);
  }
});

document.getElementById('save-config').addEventListener('click', async () => {
  const provider = getSelectedProviderKey();
  try {
    let config;
    if (hasGuidedForm(provider)) {
      config = collectGuidedConfig(provider);
      const check = validateGuidedConfig(provider, config);
      if (!check.ok) {
        alert(`Eksik alanlar: ${check.missing.join(', ')}`);
        return;
      }
      providerConfigEl.value = JSON.stringify(config, null, 2);
    } else {
      config = JSON.parse(providerConfigEl.value || '{}');
    }
    await api('/api/provider-config', {
      method: 'POST',
      body: JSON.stringify({ provider_key: provider, config, strict: false }),
    });
    alert('Config kaydedildi. Sonraki adım: Bağlantıyı Test Et');
    await loadProviders();
  } catch (err) {
    alert(`Config kaydetme hatası: ${err.message}`);
  }
});

document.getElementById('test-config').addEventListener('click', async () => {
  const provider = getSelectedProviderKey();
  try {
    const result = await api('/api/provider-test', {
      method: 'POST',
      body: JSON.stringify({ provider_key: provider }),
    });
    if (result.status === 'ok') {
      alert(`Test başarılı: ${provider}`);
    } else {
      alert(`Test başarısız (${provider}): ${JSON.stringify(result.detail)}`);
    }
  } catch (err) {
    alert(`Test hatası: ${err.message}`);
  }
});

providerSelectEl.addEventListener('change', async () => {
  const provider = getSelectedProviderKey();
  if (!provider) return;
  await loadProviderConfigIntoEditor(provider);
});

providerListEl.addEventListener('change', () => {
  saveSelectedProviders(selectedProviders());
});

urlInputEl.addEventListener('blur', async () => {
  if (!urlInputEl.value.trim()) return;
  await fetchUrlMetaAndFill(false);
});

urlInputEl.addEventListener('input', () => {
  scheduleAutoUrlMetaFetch();
});

urlInputEl.addEventListener('paste', () => {
  setTimeout(scheduleAutoUrlMetaFetch, 50);
});

async function handleFacebookConnectCallbackIfAny() {
  const url = new URL(window.location.href);
  const state = url.searchParams.get('fb_connect_state') || '';
  if (!state) return;
  pendingFacebookState = state;
  try {
    const result = await api(`/api/facebook/connect-result?state=${encodeURIComponent(state)}`);
    providerSelectEl.value = 'facebook';
    await loadProviderConfigIntoEditor('facebook');

    if (result.status === 'ok') {
      renderFacebookPagePicker(state, result.pages || []);
      if (url.searchParams.get('fb_connect_status') === 'ok') {
        alert('Facebook bağlantısı alındı. Şimdi sayfanı seç.');
      }
      return;
    }
    if (result.status === 'error') {
      alert(`Facebook bağlantı hatası: ${result.error || 'Bilinmeyen hata'}`);
      return;
    }
  } catch (err) {
    alert(`Facebook callback okuma hatası: ${err.message}`);
  }
}

(async function init() {
  await loadProviders();
  await loadLogs();
  await handleFacebookConnectCallbackIfAny();
})();
