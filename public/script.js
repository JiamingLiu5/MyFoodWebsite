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
    sidebarToggleBtn.textContent = isCollapsed ? '≡' : '×';
    sidebarToggleBtn.setAttribute('aria-label', isCollapsed ? 'Open menu' : 'Close menu');
    sidebarToggleBtn.setAttribute('title', isCollapsed ? 'Open menu' : 'Close menu');
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

  const SIDEBAR_FOLLOW_OFFSET = 12;
  let sidebarCurrentY = window.scrollY + SIDEBAR_FOLLOW_OFFSET;
  let sidebarTargetY = sidebarCurrentY;
  let sidebarFollowRafId = 0;

  function applySidebarOffset(y) {
    actionSidebar.style.transform = `translate3d(0, ${Math.round(y)}px, 0)`;
  }

  function animateSidebarFollow() {
    const delta = sidebarTargetY - sidebarCurrentY;
    if (Math.abs(delta) < 0.2) {
      sidebarCurrentY = sidebarTargetY;
      applySidebarOffset(sidebarCurrentY);
      sidebarFollowRafId = 0;
      return;
    }
    sidebarCurrentY += delta * 0.2;
    applySidebarOffset(sidebarCurrentY);
    sidebarFollowRafId = window.requestAnimationFrame(animateSidebarFollow);
  }

  function queueSidebarFollow() {
    sidebarTargetY = window.scrollY + SIDEBAR_FOLLOW_OFFSET;
    if (!sidebarFollowRafId) {
      sidebarFollowRafId = window.requestAnimationFrame(animateSidebarFollow);
    }
  }

  applySidebarOffset(sidebarCurrentY);
  window.addEventListener('scroll', queueSidebarFollow, { passive: true });
  window.addEventListener('resize', queueSidebarFollow);

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

  function tryBuildClientVideoPoster(video) {
    if (!video || video.getAttribute('poster')) return;

    let didSetPoster = false;
    const finalize = () => {
      if (didSetPoster) return;
      didSetPoster = true;
      video.classList.add('is-media-loaded');
    };

    function drawPoster() {
      try {
        const width = Number(video.videoWidth || 0);
        const height = Number(video.videoHeight || 0);
        if (width > 0 && height > 0) {
          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const context = canvas.getContext('2d');
          if (context) {
            context.drawImage(video, 0, 0, width, height);
            const dataUrl = canvas.toDataURL('image/jpeg', 0.85);
            if (dataUrl && dataUrl.startsWith('data:image/')) {
              video.setAttribute('poster', dataUrl);
            }
          }
        }
      } catch (err) {
        // Ignore poster generation failures.
      }

      try {
        video.currentTime = 0;
      } catch (err) {
        // Ignore seek reset failures.
      }
      finalize();
    }

    function captureFrame() {
      const duration = Number(video.duration || 0);
      let seekTime = 0.05;
      if (Number.isFinite(duration) && duration > 0 && duration < seekTime) {
        seekTime = Math.max(0, duration / 2);
      }
      const onSeeked = () => {
        video.removeEventListener('seeked', onSeeked);
        drawPoster();
      };
      video.addEventListener('seeked', onSeeked);
      try {
        video.currentTime = seekTime;
      } catch (err) {
        video.removeEventListener('seeked', onSeeked);
        drawPoster();
      }
    }

    if (video.readyState >= 2) {
      captureFrame();
      return;
    }

    video.addEventListener('loadeddata', captureFrame, { once: true });
    video.addEventListener('error', finalize, { once: true });
    window.setTimeout(finalize, 1800);
  }

  function attachVideoPlaybackHint(video) {
    if (!video) return;
    const source = video.querySelector('source[src]');
    const sourceUrl = source ? String(source.getAttribute('src') || '').trim() : '';
    const sourceMime = source ? String(source.getAttribute('type') || '').toLowerCase() : '';
    const isLikelyMov = sourceUrl.toLowerCase().includes('.mov') || sourceMime === 'video/quicktime';
    if (!isLikelyMov) return;

    const host = video.parentElement || video;
    const showHint = () => {
      if (!host || host.querySelector('.video-playback-hint')) return;
      const hint = document.createElement('p');
      hint.className = 'detail-hint video-playback-hint';
      hint.textContent = 'This MOV may not play in this browser. Try Safari or upload an MP4/H.264 copy. ';
      if (sourceUrl) {
        const link = document.createElement('a');
        link.href = sourceUrl;
        link.textContent = 'Download video';
        link.setAttribute('download', '');
        hint.appendChild(link);
      }
      host.appendChild(hint);
    };

    const quicktimeSupport = String(video.canPlayType('video/quicktime')).trim();
    if (!quicktimeSupport) {
      showHint();
    }
    video.addEventListener('error', showHint);
  }

  function bindMediaFade(node) {
    if (!node) return;
    const tagName = String(node.tagName || '').toLowerCase();
    if (tagName === 'img') {
      if (node.complete && node.naturalWidth > 0) {
        node.classList.add('is-media-loaded');
        return;
      }
      node.addEventListener('load', () => node.classList.add('is-media-loaded'));
      node.addEventListener('error', () => node.classList.add('is-media-loaded'));
      return;
    }
    if (tagName === 'video') {
      tryBuildClientVideoPoster(node);
      attachVideoPlaybackHint(node);
      if (node.readyState >= 1 || node.getAttribute('poster')) {
        node.classList.add('is-media-loaded');
        return;
      }
      node.addEventListener('loadeddata', () => node.classList.add('is-media-loaded'));
      node.addEventListener('loadedmetadata', () => node.classList.add('is-media-loaded'));
      node.addEventListener('canplay', () => node.classList.add('is-media-loaded'));
      node.addEventListener('error', () => node.classList.add('is-media-loaded'));
      window.setTimeout(() => node.classList.add('is-media-loaded'), 1500);
    }
  }

  document.querySelectorAll('.entry-images img, .detail-gallery img, .entry-video, .detail-video').forEach(bindMediaFade);

  const photoInput = document.querySelector('.upload-form input[name="photos"]');
  const previewWrap = document.getElementById('uploadPreview');
  const previewImg = document.getElementById('uploadPreviewImg');
  const previewName = document.getElementById('uploadPreviewName');
  const previewInfo = document.getElementById('uploadPreviewInfo');
  const previewError = document.getElementById('uploadPreviewError');

  let objectUrl = null;
  const HEIC_FILE_EXTENSIONS = new Set(['.heic', '.heif']);
  const HEIC_MIME_TYPES = new Set(['image/heic', 'image/heif', 'image/heic-sequence', 'image/heif-sequence']);
  const GENERIC_BINARY_MIME_TYPES = new Set(['', 'application/octet-stream', 'binary/octet-stream']);

  function getFileExtension(filename) {
    const name = String(filename || '');
    const match = name.match(/(\.[^./\\]+)$/);
    return match ? String(match[1]).toLowerCase() : '';
  }

  function isHeicImageFile(file) {
    const mime = String(file?.type || '').trim().toLowerCase();
    if (HEIC_MIME_TYPES.has(mime)) return true;
    const ext = getFileExtension(file?.name);
    return HEIC_FILE_EXTENSIONS.has(ext) && GENERIC_BINARY_MIME_TYPES.has(mime);
  }

  function isSupportedImageFile(file) {
    const mime = String(file?.type || '').trim().toLowerCase();
    if (mime.startsWith('image/')) return true;
    return isHeicImageFile(file);
  }

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

      if (!isSupportedImageFile(first)) {
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

  function showUploadClientError(message) {
    const fallback = 'Upload failed. Please try again.';
    const text = String(message || fallback).trim() || fallback;
    if (previewError) {
      previewError.textContent = text;
      previewError.hidden = false;
    } else {
      window.alert(text);
    }
  }

  function supportsClientOptimization() {
    return Boolean(window.fetch && window.FormData && window.File && window.Blob);
  }

  function canvasToJpegBlob(canvas, quality) {
    return new Promise((resolve) => {
      canvas.toBlob((blob) => resolve(blob || null), 'image/jpeg', quality);
    });
  }

  function loadImageFromFile(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const blobUrl = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(blobUrl);
        resolve(img);
      };
      img.onerror = () => {
        URL.revokeObjectURL(blobUrl);
        reject(new Error('Failed to decode image'));
      };
      img.src = blobUrl;
    });
  }

  function buildJpgName(filename) {
    const name = String(filename || 'upload').replace(/\.[^./\\]+$/, '');
    return `${name}.jpg`;
  }

  async function optimizePhotoFile(file) {
    const mime = String(file?.type || '').toLowerCase();
    if (!isSupportedImageFile(file)) return file;
    if (!mime.startsWith('image/')) return file;
    if (mime === 'image/gif' || mime === 'image/png' || mime === 'image/svg+xml') return file;
    if (mime.includes('heic') || mime.includes('heif')) return file;

    const CLIENT_IMAGE_MIN_BYTES = 420 * 1024;
    const CLIENT_IMAGE_MAX_DIMENSION = 1920;
    const CLIENT_IMAGE_QUALITY = 0.82;

    if (Number(file.size || 0) < CLIENT_IMAGE_MIN_BYTES) return file;

    try {
      const source = await loadImageFromFile(file);
      const sourceW = Math.max(1, Number(source.naturalWidth || source.width || 1));
      const sourceH = Math.max(1, Number(source.naturalHeight || source.height || 1));
      const scale = Math.min(1, CLIENT_IMAGE_MAX_DIMENSION / Math.max(sourceW, sourceH));
      const targetW = Math.max(1, Math.round(sourceW * scale));
      const targetH = Math.max(1, Math.round(sourceH * scale));

      if (targetW === sourceW && targetH === sourceH && file.size < 900 * 1024) return file;

      const canvas = document.createElement('canvas');
      canvas.width = targetW;
      canvas.height = targetH;
      const context = canvas.getContext('2d');
      if (!context) return file;
      context.drawImage(source, 0, 0, targetW, targetH);

      const blob = await canvasToJpegBlob(canvas, CLIENT_IMAGE_QUALITY);
      if (!blob || blob.size <= 0) return file;
      if (blob.size >= file.size * 0.97) return file;

      return new File([blob], buildJpgName(file.name), {
        type: 'image/jpeg',
        lastModified: Date.now()
      });
    } catch (err) {
      return file;
    }
  }

  async function optimizePhotoFiles(files) {
    const optimized = [];
    for (const file of files) {
      // Sequential processing avoids freezing low-end devices on large batches.
      // eslint-disable-next-line no-await-in-loop
      optimized.push(await optimizePhotoFile(file));
    }
    return optimized;
  }

  function setUploadFormBusy(form, isBusy) {
    form.dataset.clientBusy = isBusy ? '1' : '0';
    const buttons = Array.from(form.querySelectorAll('button[type="submit"]'));
    buttons.forEach((button) => {
      if (isBusy) {
        if (!button.dataset.originalText) button.dataset.originalText = button.textContent || '';
        button.disabled = true;
        button.textContent = 'Uploading...';
      } else {
        button.disabled = false;
        if (button.dataset.originalText) button.textContent = button.dataset.originalText;
      }
    });
  }

  async function submitOptimizedUploadForm(form) {
    if (form.dataset.clientBusy === '1') return;
    const photosInput = form.querySelector('input[name="photos"]');
    const videoInput = form.querySelector('input[name="video"]');
    if (!photosInput) {
      form.submit();
      return;
    }

    const maxImageCount = Number.parseInt(photosInput.dataset.maxCount || '10', 10) || 10;
    const maxVideoMb = Number.parseInt((videoInput && videoInput.dataset.maxSizeMb) || '50', 10) || 50;
    const maxVideoBytes = maxVideoMb * 1024 * 1024;
    const selectedPhotos = Array.from(photosInput.files || []);
    const selectedVideo = videoInput && videoInput.files ? Array.from(videoInput.files) : [];

    if (selectedPhotos.length > maxImageCount) {
      showUploadClientError(`You can upload up to ${maxImageCount} images per post.`);
      return;
    }
    if (selectedVideo.length > 1) {
      showUploadClientError('You can upload only 1 video per post.');
      return;
    }
    if (selectedVideo[0] && Number(selectedVideo[0].size || 0) > maxVideoBytes) {
      showUploadClientError(`Video must be ${maxVideoMb}MB or smaller.`);
      return;
    }

    if (previewError) {
      previewError.hidden = true;
      previewError.textContent = '';
    }

    setUploadFormBusy(form, true);
    try {
      const optimizedPhotos = await optimizePhotoFiles(selectedPhotos);
      const formData = new FormData(form);
      formData.delete('photos');
      optimizedPhotos.forEach((file) => formData.append('photos', file, file.name));
      formData.delete('video');
      if (selectedVideo[0]) formData.append('video', selectedVideo[0], selectedVideo[0].name);

      const response = await fetch(form.action, {
        method: (form.method || 'post').toUpperCase(),
        body: formData,
        credentials: 'same-origin',
        redirect: 'follow'
      });
      const contentType = String(response.headers.get('content-type') || '').toLowerCase();

      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }

      if (contentType.includes('text/html')) {
        const html = await response.text();
        document.open();
        document.write(html);
        document.close();
        return;
      }

      if (response.ok) {
        window.location.reload();
        return;
      }

      const errorText = (await response.text()).trim();
      showUploadClientError(errorText || `Upload failed (${response.status}).`);
    } catch (err) {
      showUploadClientError('Upload failed while optimizing media. Please try again.');
    } finally {
      setUploadFormBusy(form, false);
    }
  }

  if (supportsClientOptimization()) {
    const uploadForms = Array.from(document.querySelectorAll('form.upload-form'))
      .filter((form) => form.querySelector('input[name="photos"]'));
    uploadForms.forEach((form) => {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        submitOptimizedUploadForm(form);
      });
    });
  }

  function bindReactionForms() {
    const reactionForms = Array.from(document.querySelectorAll('form.reaction-form'));
    if (!reactionForms.length || !window.fetch || !window.FormData) return;

    let reactionBusy = false;

    function setReactionBusy(isBusy) {
      reactionBusy = isBusy;
      reactionForms.forEach((form) => {
        const button = form.querySelector('button[type="submit"]');
        if (!button) return;
        button.disabled = isBusy;
      });
    }

    function updateReactionButtons(reactionsState) {
      const counts = (reactionsState && reactionsState.counts) || {};
      const mine = reactionsState ? reactionsState.mine : null;
      reactionForms.forEach((form) => {
        const reaction = String(
          form.getAttribute('data-reaction') ||
          (form.querySelector('input[name="reaction"]') && form.querySelector('input[name="reaction"]').value) ||
          ''
        ).trim().toLowerCase();
        const button = form.querySelector('button[type="submit"]');
        if (!reaction || !button) return;
        const count = Number(counts[reaction] || 0);
        button.textContent = `${reaction} (${count})`;
        button.className = mine === reaction ? 'pin-btn' : 'view-btn';
        button.setAttribute('aria-pressed', mine === reaction ? 'true' : 'false');
      });
    }

    reactionForms.forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (reactionBusy) return;
        setReactionBusy(true);

        try {
          const payload = new URLSearchParams();
          new FormData(form).forEach((value, key) => {
            payload.append(key, String(value));
          });

          const response = await fetch(form.action, {
            method: 'POST',
            body: payload.toString(),
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
              Accept: 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            }
          });

          if (response.redirected) {
            window.location.assign(response.url);
            return;
          }

          const contentType = String(response.headers.get('content-type') || '').toLowerCase();
          if (!contentType.includes('application/json')) {
            window.location.reload();
            return;
          }

          const responsePayload = await response.json();
          if (!response.ok || !responsePayload || responsePayload.ok !== true) {
            const message = (responsePayload && responsePayload.error) ? responsePayload.error : `Reaction failed (${response.status}).`;
            window.alert(message);
            return;
          }

          updateReactionButtons(responsePayload.reactions);
        } catch (err) {
          window.alert('Reaction request failed. Please try again.');
        } finally {
          setReactionBusy(false);
        }
      });
    });
  }

  bindReactionForms();

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
