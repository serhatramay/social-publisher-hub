const providerListEl = document.getElementById('provider-list');
const providerSelectEl = document.getElementById('provider-select');
const providerConfigEl = document.getElementById('provider-config');
const logsEl = document.getElementById('logs');

let providers = [];

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

function renderProviders() {
  providerListEl.innerHTML = '';
  providerSelectEl.innerHTML = '';

  providers.forEach((p) => {
    const wrapper = document.createElement('div');
    wrapper.className = `provider-item ${p.mode}`;

    const id = `provider-${p.key}`;
    wrapper.innerHTML = `
      <label>
        <input type="checkbox" id="${id}" value="${p.key}" />
        ${p.label}
      </label>
      <div class="provider-meta">
        mode: ${p.mode} | configured: ${p.configured ? 'yes' : 'no'}
      </div>
      <div class="provider-meta">${p.notes || ''}</div>
    `;

    providerListEl.appendChild(wrapper);

    const opt = document.createElement('option');
    opt.value = p.key;
    opt.textContent = `${p.label} (${p.key})`;
    providerSelectEl.appendChild(opt);
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
}

async function loadLogs() {
  const data = await api('/api/deliveries');
  renderLogs(data.items || []);
}

document.getElementById('publish-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const selected = Array.from(providerListEl.querySelectorAll('input[type="checkbox"]:checked'))
    .map((x) => x.value);

  const payload = {
    title: document.getElementById('title').value.trim(),
    url: document.getElementById('url').value.trim(),
    text_body: document.getElementById('text_body').value.trim(),
    image_url: document.getElementById('image_url').value.trim(),
    providers: selected,
  };

  try {
    const result = await api('/api/publish', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    alert(`Gönderim tamamlandı. Post ID: ${result.post_id}`);
    await loadProviders();
    await loadLogs();
  } catch (err) {
    alert(`Hata: ${err.message}`);
  }
});

document.getElementById('load-template').addEventListener('click', async () => {
  const provider = providerSelectEl.value;
  try {
    const data = await api(`/api/provider-config-template?provider=${encodeURIComponent(provider)}`);
    providerConfigEl.value = JSON.stringify(data.template || {}, null, 2);
  } catch (err) {
    alert(`Template alınamadı: ${err.message}`);
  }
});

document.getElementById('save-config').addEventListener('click', async () => {
  const provider = providerSelectEl.value;
  try {
    const config = JSON.parse(providerConfigEl.value || '{}');
    await api('/api/provider-config', {
      method: 'POST',
      body: JSON.stringify({ provider_key: provider, config }),
    });
    alert('Config kaydedildi');
    await loadProviders();
  } catch (err) {
    alert(`Config kaydetme hatası: ${err.message}`);
  }
});

(async function init() {
  await loadProviders();
  await loadLogs();
})();
