const providerListEl = document.getElementById('provider-list');
const providerSelectEl = document.getElementById('provider-select');
const providerConfigEl = document.getElementById('provider-config');
const providerFormFieldsEl = document.getElementById('provider-form-fields');
const logsEl = document.getElementById('logs');
const publishChecksEl = document.getElementById('publish-checks');

let providers = [];
let providerTemplates = {};

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
    providerConfigEl.value = JSON.stringify(merged, null, 2);
  } catch (err) {
    renderProviderConfigFields(providerKey, {});
    providerConfigEl.value = '{}';
    alert(`Config yükleme hatası: ${err.message}`);
  }
}

function renderProviders() {
  providerListEl.innerHTML = '';
  providerSelectEl.innerHTML = '';

  providers.forEach((p) => {
    const wrapper = document.createElement('div');
    wrapper.className = `provider-item ${p.mode} ${p.status} phase-${p.phase}`;

    const id = `provider-${p.key}`;
    wrapper.innerHTML = `
      <label>
        <input type="checkbox" id="${id}" value="${p.key}" />
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

function renderPublishChecks(items) {
  publishChecksEl.innerHTML = '';
  if (!items || !items.length) return;
  items.forEach((it) => {
    const ok = it.config_ok && it.post_ok;
    const div = document.createElement('div');
    div.className = 'check-item';
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

  try {
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
    const failed = (result.results || []).filter((x) => x.status !== 'ok').length;
    alert(`Gönderim tamamlandı. Post ID: ${result.post_id}. Başarısız: ${failed}`);
    await loadProviders();
    await loadLogs();
  } catch (err) {
    alert(`Hata: ${err.message}`);
  }
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

(async function init() {
  await loadProviders();
  await loadLogs();
})();
