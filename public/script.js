document.addEventListener('DOMContentLoaded', () => {
  const photoInput = document.querySelector('.upload-form input[name="photo"]');
  if (!photoInput) return;

  const previewWrap = document.getElementById('uploadPreview');
  const previewImg = document.getElementById('uploadPreviewImg');
  const previewName = document.getElementById('uploadPreviewName');
  const previewInfo = document.getElementById('uploadPreviewInfo');
  const previewError = document.getElementById('uploadPreviewError');

  let objectUrl = null;

  function resetPreview() {
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

  photoInput.addEventListener('change', () => {
    resetPreview();

    const file = photoInput.files && photoInput.files[0];
    if (!file) return;

    previewName.textContent = file.name || 'Selected image';
    const sizeKb = Math.max(1, Math.round((file.size || 0) / 1024));
    previewInfo.textContent = `${sizeKb} KB`;

    if (file.type && !file.type.startsWith('image/')) {
      previewError.textContent = 'Selected file is not an image.';
      previewError.hidden = false;
      return;
    }

    objectUrl = URL.createObjectURL(file);
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

  window.addEventListener('beforeunload', () => {
    if (objectUrl) {
      URL.revokeObjectURL(objectUrl);
    }
  });
});
