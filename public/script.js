document.addEventListener('DOMContentLoaded', () => {
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
        previewWrap.hidden = false;
      };
      previewImg.onerror = () => {
        previewError.textContent = 'This image format cannot be previewed here, but upload may still work.';
        previewError.hidden = false;
        previewImg.removeAttribute('src');
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
