const THEME_STORAGE_KEY = 'myfood_theme_v1';
const SIDEBAR_COLLAPSED_STORAGE_KEY = 'myfood_sidebar_collapsed_v1';
const THEME_PRESETS = [
  { id: 'sunkeep', name: 'Sunkeep' },
  { id: 'moonharbor', name: 'Moonharbor' },
  { id: 'wildgrove', name: 'Wildgrove' }
];

function resolveTheme(themeId) {
  const match = THEME_PRESETS.find((theme) => theme.id === themeId);
  return match ? match.id : THEME_PRESETS[0].id;
}

function applyTheme(themeId) {
  const resolved = resolveTheme(themeId);
  document.documentElement.setAttribute('data-theme', resolved);
  return resolved;
}

(() => {
  try {
    const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    applyTheme(savedTheme);
  } catch (err) {
    applyTheme(null);
  }
})();

document.addEventListener('DOMContentLoaded', () => {
  const loadingBar = document.createElement('div');
  loadingBar.className = 'page-loading-bar';
  document.body.appendChild(loadingBar);
  window.setTimeout(() => {
    loadingBar.classList.add('is-done');
    window.setTimeout(() => loadingBar.remove(), 380);
  }, 450);

  let activeTheme = applyTheme(document.documentElement.getAttribute('data-theme'));
  const themeSwitcher = document.createElement('div');
  themeSwitcher.className = 'theme-switcher';
  themeSwitcher.innerHTML = `
    <button class="theme-toggle" type="button" aria-haspopup="true" aria-expanded="false" aria-label="Open theme switcher">
      <span>Realm</span>
      <strong class="theme-toggle-name"></strong>
    </button>
    <div class="theme-menu" role="menu" aria-label="Theme options">
      ${THEME_PRESETS.map((theme) => `
        <button class="theme-option" type="button" role="menuitemradio" data-theme="${theme.id}">
          <span class="theme-option-name">${theme.name}</span>
          <span class="theme-option-dot"></span>
        </button>
      `).join('')}
    </div>
  `;
  document.body.appendChild(themeSwitcher);

  const themeToggleBtn = themeSwitcher.querySelector('.theme-toggle');
  const themeName = themeSwitcher.querySelector('.theme-toggle-name');
  const themeOptions = Array.from(themeSwitcher.querySelectorAll('.theme-option'));

  function syncThemeUI(themeId) {
    const selectedTheme = THEME_PRESETS.find((theme) => theme.id === themeId) || THEME_PRESETS[0];
    if (themeName) themeName.textContent = selectedTheme.name;
    themeOptions.forEach((option) => {
      const isActive = option.dataset.theme === selectedTheme.id;
      option.classList.toggle('is-active', isActive);
      option.setAttribute('aria-checked', String(isActive));
    });
  }

  function setTheme(themeId, options = {}) {
    const persist = options.persist !== false;
    activeTheme = applyTheme(themeId);
    if (persist) {
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, activeTheme);
      } catch (err) {
        // Ignore storage failures in private browsing modes.
      }
    }
    syncThemeUI(activeTheme);
  }

  function setMenuOpen(isOpen) {
    themeSwitcher.classList.toggle('is-open', isOpen);
    themeToggleBtn.setAttribute('aria-expanded', String(isOpen));
  }

  setTheme(activeTheme, { persist: false });

  themeToggleBtn.addEventListener('click', () => {
    const isOpen = !themeSwitcher.classList.contains('is-open');
    setMenuOpen(isOpen);
  });

  themeOptions.forEach((option) => {
    option.addEventListener('click', () => {
      setTheme(option.dataset.theme || THEME_PRESETS[0].id);
      setMenuOpen(false);
    });
  });

  document.addEventListener('click', (event) => {
    if (!themeSwitcher.contains(event.target)) setMenuOpen(false);
  });

  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') setMenuOpen(false);
  });

  const searchToggleBtn = document.getElementById('searchToggleBtn');
  const searchPanel = document.getElementById('searchPanel');
  if (searchToggleBtn && searchPanel) {
    function setSearchOpen(isOpen) {
      searchPanel.hidden = !isOpen;
      searchToggleBtn.setAttribute('aria-expanded', String(isOpen));
      searchToggleBtn.textContent = isOpen ? 'Hide Search' : 'Show Search';
    }

    setSearchOpen(searchToggleBtn.getAttribute('aria-expanded') === 'true');
    searchToggleBtn.addEventListener('click', () => {
      const isOpen = searchToggleBtn.getAttribute('aria-expanded') !== 'true';
      setSearchOpen(isOpen);
    });
  }

  function buildSidebarButton(href, label) {
    const link = document.createElement('a');
    link.href = href;
    link.className = 'sidebar-btn';
    link.textContent = label;
    return link;
  }

  function normalizeLabel(text) {
    return String(text || '').replace(/\s+/g, ' ').trim();
  }

  function getCurrentPath() {
    return `${window.location.pathname}${window.location.search || ''}`;
  }

  const actionSidebar = document.createElement('aside');
  actionSidebar.className = 'action-sidebar';
  const sidebarToggleBtn = document.createElement('button');
  sidebarToggleBtn.type = 'button';
  sidebarToggleBtn.className = 'sidebar-fold-toggle sidebar-btn';
  sidebarToggleBtn.setAttribute('aria-controls', 'actionSidebarBody');
  const sidebarBody = document.createElement('div');
  sidebarBody.className = 'action-sidebar-body';
  sidebarBody.id = 'actionSidebarBody';
  const sidebarMain = document.createElement('div');
  sidebarMain.className = 'action-sidebar-main';
  const sidebarInfo = document.createElement('div');
  sidebarInfo.className = 'action-sidebar-info';
  const addedSidebarKeys = new Set();

  function addSidebarInfo(text) {
    const label = normalizeLabel(text);
    if (!label) return;
    const info = document.createElement('div');
    info.className = 'sidebar-info';
    info.textContent = label;
    sidebarInfo.appendChild(info);
  }

  function addSidebarLink(href, text) {
    const label = normalizeLabel(text);
    if (!href || !label) return;
    const key = `link:${href}:${label.toLowerCase()}`;
    if (addedSidebarKeys.has(key)) return;
    addedSidebarKeys.add(key);
    const btn = buildSidebarButton(href, label);
    if (href === getCurrentPath() || href === window.location.pathname) {
      btn.classList.add('is-active');
    }
    sidebarMain.appendChild(btn);
  }

  function addSidebarForm(formNode) {
    if (!formNode) return;
    const action = formNode.getAttribute('action') || '';
    const key = `form:${formNode.getAttribute('method') || 'get'}:${action}`;
    if (addedSidebarKeys.has(key)) return;
    addedSidebarKeys.add(key);
    const cloned = formNode.cloneNode(true);
    cloned.classList.add('sidebar-form');
    const button = cloned.querySelector('button');
    if (button) {
      button.className = 'sidebar-btn';
      const currentLabel = normalizeLabel(button.textContent);
      button.textContent = currentLabel || 'Submit';
    }
    sidebarMain.appendChild(cloned);
  }

  if (searchToggleBtn) {
    searchToggleBtn.classList.add('sidebar-btn');
    sidebarMain.appendChild(searchToggleBtn);
  }

  const topNavs = Array.from(document.querySelectorAll('.top-nav'));
  let hasLogoutControl = false;
  topNavs.forEach((topNav) => {
    const infoNodes = Array.from(topNav.children).filter((child) => child.tagName === 'SPAN');
    infoNodes.forEach((node) => {
      addSidebarInfo(node.textContent);
      node.remove();
    });

    const links = Array.from(topNav.querySelectorAll('a[href]'));
    links.forEach((link) => {
      addSidebarLink(link.getAttribute('href'), link.textContent);
      link.remove();
    });

    const forms = Array.from(topNav.querySelectorAll('form'));
    forms.forEach((formNode) => {
      if ((formNode.getAttribute('action') || '').trim() === '/logout') {
        hasLogoutControl = true;
      }
      addSidebarForm(formNode);
      formNode.remove();
    });

    if (!topNav.querySelector('a, form, button, span')) {
      topNav.classList.add('is-empty');
    }
  });

  if (!hasLogoutControl) {
    const hasLoginHint = Boolean(document.querySelector('a[href="/login"]')) || window.location.pathname === '/register';
    const hasRegisterHint = Boolean(document.querySelector('a[href="/register"]')) || window.location.pathname === '/login';
    if (hasLoginHint) addSidebarLink('/login', 'Login');
    if (hasRegisterHint) addSidebarLink('/register', 'Register');
  }

  if (!addedSidebarKeys.has('link:/:home')) {
    addSidebarLink('/', 'Home');
  }

  themeSwitcher.classList.add('theme-switcher-in-sidebar');
  if (sidebarInfo.childElementCount > 0) {
    sidebarBody.appendChild(sidebarInfo);
  }
  sidebarBody.appendChild(sidebarMain);
  sidebarBody.appendChild(themeSwitcher);
  actionSidebar.appendChild(sidebarToggleBtn);
  actionSidebar.appendChild(sidebarBody);
  document.body.appendChild(actionSidebar);
  document.body.classList.add('has-action-sidebar');

  function setSidebarCollapsed(isCollapsed, options = {}) {
    const persist = options.persist !== false;
    actionSidebar.classList.toggle('is-collapsed', isCollapsed);
    document.body.classList.toggle('sidebar-collapsed', isCollapsed);
    sidebarToggleBtn.setAttribute('aria-expanded', String(!isCollapsed));
    sidebarToggleBtn.textContent = isCollapsed ? 'Open Menu' : 'Hide Menu';
    if (isCollapsed) setMenuOpen(false);
    if (persist) {
      try {
        window.localStorage.setItem(SIDEBAR_COLLAPSED_STORAGE_KEY, isCollapsed ? '1' : '0');
      } catch (err) {
        // Ignore storage failures.
      }
    }
  }

  let sidebarStartsCollapsed = true;
  try {
    const savedSidebarState = window.localStorage.getItem(SIDEBAR_COLLAPSED_STORAGE_KEY);
    if (savedSidebarState === '0') sidebarStartsCollapsed = false;
    if (savedSidebarState === '1') sidebarStartsCollapsed = true;
  } catch (err) {
    // Keep default collapsed state.
  }
  setSidebarCollapsed(sidebarStartsCollapsed, { persist: false });
  sidebarToggleBtn.addEventListener('click', () => {
    const isCollapsed = actionSidebar.classList.contains('is-collapsed');
    setSidebarCollapsed(!isCollapsed);
  });

  const entries = Array.from(document.querySelectorAll('.entry'));
  if (entries.length) {
    document.body.classList.add('enable-reveal');
    entries.forEach((entry, index) => {
      entry.style.setProperty('--stagger-index', String(index));
    });

    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(
        (items) => {
          items.forEach((item) => {
            if (item.isIntersecting) {
              item.target.classList.add('is-visible');
              observer.unobserve(item.target);
            }
          });
        },
        { threshold: 0.1 }
      );
      entries.forEach((entry) => observer.observe(entry));
    } else {
      entries.forEach((entry) => entry.classList.add('is-visible'));
    }
  }

  function bindMediaFade(img) {
    if (!img) return;
    if (img.complete && img.naturalWidth > 0) {
      img.classList.add('is-media-loaded');
      return;
    }
    img.addEventListener('load', () => img.classList.add('is-media-loaded'));
    img.addEventListener('error', () => img.classList.add('is-media-loaded'));
  }

  document.querySelectorAll('.entry-images img, .detail-gallery img').forEach(bindMediaFade);

  const photoInput = document.querySelector('.upload-form input[name="photos"]');
  const previewWrap = document.getElementById('uploadPreview');
  const previewImg = document.getElementById('uploadPreviewImg');
  const previewName = document.getElementById('uploadPreviewName');
  const previewInfo = document.getElementById('uploadPreviewInfo');
  const previewError = document.getElementById('uploadPreviewError');

  let objectUrl = null;

  function resetPreview() {
    if (!previewWrap || !previewImg || !previewName || !previewInfo || !previewError) return;
    if (objectUrl) {
      URL.revokeObjectURL(objectUrl);
      objectUrl = null;
    }
    previewWrap.hidden = true;
    previewError.hidden = true;
    previewImg.removeAttribute('src');
    previewImg.classList.remove('is-media-loaded');
    previewName.textContent = '';
    previewInfo.textContent = '';
    previewError.textContent = '';
  }

  if (photoInput && previewWrap && previewImg && previewName && previewInfo && previewError) {
    photoInput.addEventListener('change', () => {
      resetPreview();

      const files = Array.from(photoInput.files || []);
      if (!files.length) return;

      const first = files[0];
      previewName.textContent = first.name || 'Selected image';
      const totalBytes = files.reduce((sum, file) => sum + (file.size || 0), 0);
      const totalMb = (totalBytes / (1024 * 1024)).toFixed(2);
      previewInfo.textContent = `${files.length} image(s), ${totalMb} MB total`;

      if (first.type && !first.type.startsWith('image/')) {
        previewError.textContent = 'Selected file is not an image.';
        previewError.hidden = false;
        return;
      }

      objectUrl = URL.createObjectURL(first);
      previewImg.onload = () => {
        previewImg.classList.add('is-media-loaded');
        previewWrap.hidden = false;
      };
      previewImg.onerror = () => {
        previewError.textContent = 'This image format cannot be previewed here, but upload may still work.';
        previewError.hidden = false;
        previewImg.removeAttribute('src');
        previewImg.classList.remove('is-media-loaded');
        if (objectUrl) {
          URL.revokeObjectURL(objectUrl);
          objectUrl = null;
        }
      };
      previewImg.src = objectUrl;
    });
  }

  const lightboxLinks = Array.from(document.querySelectorAll('[data-lightbox]'));
  if (lightboxLinks.length) {
    const lightbox = document.createElement('div');
    lightbox.className = 'lightbox';
    lightbox.innerHTML = '<button class="lightbox-close" type="button" aria-label="Close image viewer">×</button><img alt="Full size photo" />';
    document.body.appendChild(lightbox);

    const closeBtn = lightbox.querySelector('.lightbox-close');
    const fullImage = lightbox.querySelector('img');

    function closeLightbox() {
      lightbox.classList.remove('is-open');
      fullImage.removeAttribute('src');
    }

    lightboxLinks.forEach((link) => {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        const href = link.getAttribute('href');
        if (!href) return;
        fullImage.src = href;
        lightbox.classList.add('is-open');
      });
    });

    closeBtn.addEventListener('click', closeLightbox);
    lightbox.addEventListener('click', (event) => {
      if (event.target === lightbox) closeLightbox();
    });
    window.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeLightbox();
    });
  }

  window.addEventListener('beforeunload', () => {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
  });
});
