const AUTH_TEXT = 'I AM AUTHORIZED TO SCAN THIS PROJECT';

document.querySelectorAll('[data-open-modal]').forEach((button) => {
  button.addEventListener('click', () => document.getElementById(button.dataset.openModal)?.showModal());
});
document.querySelectorAll('[data-close-modal]').forEach((button) => {
  button.addEventListener('click', () => button.closest('dialog')?.close());
});
document.querySelectorAll('dialog').forEach((dialog) => {
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
});
document.querySelectorAll('[data-authorization-form]').forEach((form) => {
  const input = form.querySelector('[data-auth-input]');
  const checkbox = form.querySelector('input[type="checkbox"]');
  const submit = form.querySelector('[data-scan-submit]');
  const update = () => { submit.disabled = !(checkbox.checked && input.value.trim() === AUTH_TEXT); };
  input.addEventListener('input', update);
  checkbox.addEventListener('change', update);
});

const scanPanel = document.querySelector('[data-scan-status]');
if (scanPanel && !['completed', 'failed'].includes(scanPanel.dataset.currentStatus)) {
  const poll = async () => {
    try {
      const response = await fetch(scanPanel.dataset.statusUrl, {headers: {'Accept': 'application/json'}});
      if (!response.ok) return;
      const data = await response.json();
      scanPanel.querySelector('[data-status]').textContent = data.status;
      scanPanel.querySelector('[data-status]').className = `badge ${data.status}`;
      scanPanel.querySelector('[data-stage]').textContent = data.stage;
      scanPanel.querySelector('[data-progress-label]').textContent = `${data.progress}%`;
      scanPanel.querySelector('[data-progress-bar]').style.width = `${data.progress}%`;
      if (['completed', 'failed'].includes(data.status)) window.setTimeout(() => window.location.reload(), 500);
      else window.setTimeout(poll, 1200);
    } catch (_) { window.setTimeout(poll, 2500); }
  };
  window.setTimeout(poll, 900);
}

