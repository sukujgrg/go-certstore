'use strict';

const tabs = [...document.querySelectorAll('[role="tab"]')];

function activateTab(tab) {
  tabs.forEach((item) => {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
  });
  scheduleSidebarHighlight();
}

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => activateTab(tab));
  tab.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    let next = index;
    if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    activateTab(tabs[next]);
    tabs[next].focus();
  });
});

function syncBackendTabFromHash() {
  const backend = { '#native': 'native', '#pkcs11': 'pkcs11', '#nss': 'nss' }[window.location.hash];
  if (!backend) return;
  activateTab(document.querySelector(`[data-tab="${backend}"]`));
  window.requestAnimationFrame(() => document.querySelector(window.location.hash)?.scrollIntoView());
}

document.querySelectorAll('.copy-button').forEach((button) => {
  button.addEventListener('click', async () => {
    const code = button.closest('.code-block').querySelector('code').textContent;
    try {
      await navigator.clipboard.writeText(code);
      button.textContent = 'Copied';
      window.setTimeout(() => { button.textContent = 'Copy'; }, 1300);
    } catch {
      button.textContent = 'Select code';
    }
  });
});

const sidebar = document.querySelector('.sidebar');
const menuButton = document.querySelector('.menu-button');
menuButton.addEventListener('click', () => {
  const open = sidebar.classList.toggle('open');
  menuButton.setAttribute('aria-expanded', String(open));
});
document.querySelectorAll('.sidebar a').forEach((link) => link.addEventListener('click', () => {
  if (link.dataset.backendLink) activateTab(document.querySelector(`[data-tab="${link.dataset.backendLink}"]`));
  sidebar.classList.remove('open');
  menuButton.setAttribute('aria-expanded', 'false');
}));

const localLinks = [...document.querySelectorAll('.sidebar a[href^="#"]')];
const trackedSections = [...document.querySelectorAll('.doc-section[id]')];
let highlightFrame;

function updateSidebarHighlight() {
  const header = document.querySelector('.site-header');
  const activationLine = header.getBoundingClientRect().height + 24;
  let current = trackedSections[0];

  trackedSections.forEach((section) => {
    if (section.getBoundingClientRect().top <= activationLine) current = section;
  });

  if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
    current = trackedSections[trackedSections.length - 1];
  }

  const selectedBackend = document.querySelector('[role="tab"][aria-selected="true"]')?.dataset.tab;
  const activeID = current.id === 'backends' ? selectedBackend : current.id;
  localLinks.forEach((link) => link.classList.toggle('active', link.getAttribute('href') === `#${activeID}`));
}

function scheduleSidebarHighlight() {
  if (highlightFrame) return;
  highlightFrame = window.requestAnimationFrame(() => {
    highlightFrame = undefined;
    updateSidebarHighlight();
  });
}

window.addEventListener('scroll', scheduleSidebarHighlight, { passive: true });
window.addEventListener('resize', scheduleSidebarHighlight);
window.addEventListener('hashchange', syncBackendTabFromHash);
syncBackendTabFromHash();
updateSidebarHighlight();
