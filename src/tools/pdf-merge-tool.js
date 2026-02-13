const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

function createPdfMergeTool(options = {}) {
  const ghostscriptPath = String(options.ghostscriptPath || 'gs').trim() || 'gs';
  const maxFiles = Math.max(2, Number.parseInt(options.maxFiles || '10', 10));
  const maxFileSizeMb = Math.max(1, Number.parseInt(options.maxFileSizeMb || '20', 10));
  const maxTotalInputSizeMb = Math.max(
    1,
    Number.parseInt(
      options.maxTotalInputSizeMb || String(Math.min(maxFiles * maxFileSizeMb, 80)),
      10
    )
  );
  const executionTimeoutSeconds = Math.max(
    5,
    Number.parseInt(options.executionTimeoutSeconds || '45', 10)
  );
  const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024;
  const maxTotalInputSizeBytes = maxTotalInputSizeMb * 1024 * 1024;
  const executionTimeoutMs = executionTimeoutSeconds * 1000;

  let ghostscriptAvailabilityChecked = false;
  let ghostscriptAvailable = false;

  function getNormalizedMimeType(value) {
    return String(value || '').trim().toLowerCase();
  }

  function getFileExtensionFromUpload(file) {
    return path.extname(String(file?.originalname || '')).toLowerCase();
  }

  function isPdfUpload(file) {
    if (!file || typeof file !== 'object') return false;
    const mime = getNormalizedMimeType(file.mimetype);
    if (mime === 'application/pdf') return true;
    return getFileExtensionFromUpload(file) === '.pdf';
  }

  async function checkGhostscriptAvailable() {
    if (ghostscriptAvailabilityChecked) return ghostscriptAvailable;
    ghostscriptAvailabilityChecked = true;
    ghostscriptAvailable = await new Promise((resolve) => {
      const child = spawn(ghostscriptPath, ['--version'], { stdio: 'ignore' });
      child.on('error', () => resolve(false));
      child.on('close', (code) => resolve(code === 0));
    });
    if (!ghostscriptAvailable) {
      console.warn('Ghostscript not available; PDF merge tool is disabled.');
    }
    return ghostscriptAvailable;
  }

  function runGhostscript(args) {
    return new Promise((resolve, reject) => {
      const child = spawn(ghostscriptPath, args, { stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = '';
      let settled = false;
      const timeoutId = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        reject(new Error(`PDF merge timed out after ${executionTimeoutSeconds} seconds.`));
      }, executionTimeoutMs);
      child.stderr.on('data', (chunk) => {
        if (!chunk) return;
        stderr += chunk.toString();
        if (stderr.length > 3000) stderr = stderr.slice(-3000);
      });
      child.on('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        reject(err);
      });
      child.on('close', (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        if (code === 0) return resolve();
        return reject(new Error(`ghostscript exited with code ${code}: ${stderr}`));
      });
    });
  }

  function normalizeTempFilename(value, fallback) {
    const sanitized = String(value || '').replace(/[^a-z0-9.\-\_]/gi, '_');
    if (!sanitized) return fallback;
    return sanitized.slice(0, 80);
  }

  function normalizeOutputFilename(value) {
    const fallback = `merged-${Date.now()}.pdf`;
    const trimmed = String(value || '').trim();
    if (!trimmed) return fallback;
    const sanitized = trimmed.replace(/[^a-z0-9.\-\_]/gi, '_').slice(0, 120);
    if (!sanitized) return fallback;
    return sanitized.toLowerCase().endsWith('.pdf') ? sanitized : `${sanitized}.pdf`;
  }

  async function hasPdfHeader(file) {
    const probeLength = 1024;
    const headerToken = Buffer.from('%PDF-');
    const containsHeader = (buffer) => {
      if (!Buffer.isBuffer(buffer) || buffer.length === 0) return false;
      const sample = buffer.subarray(0, Math.min(buffer.length, probeLength));
      return sample.includes(headerToken);
    };

    if (Buffer.isBuffer(file?.buffer)) {
      return containsHeader(file.buffer);
    }
    if (file && typeof file.path === 'string' && file.path) {
      const handle = await fs.promises.open(file.path, 'r');
      try {
        const sample = Buffer.alloc(probeLength);
        const { bytesRead } = await handle.read(sample, 0, probeLength, 0);
        return containsHeader(sample.subarray(0, bytesRead));
      } finally {
        await handle.close();
      }
    }
    return false;
  }

  function resolveInputPathFromFile(file) {
    if (file && typeof file.path === 'string' && file.path) {
      const resolved = path.resolve(file.path);
      const tmpRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
      if (resolved.startsWith(tmpRoot)) return resolved;
      return null;
    }
    if (!Buffer.isBuffer(file?.buffer)) return null;
    return null;
  }

  async function mergePdfFiles(files) {
    if (!Array.isArray(files) || files.length < 2) {
      throw new Error('Please select at least 2 PDF files to merge.');
    }
    if (files.length > maxFiles) {
      throw new Error(`You can upload up to ${maxFiles} PDF files at once.`);
    }
    const ghostscriptReady = await checkGhostscriptAvailable();
    if (!ghostscriptReady) {
      throw new Error('PDF merge is unavailable because Ghostscript is not installed on this server.');
    }

    let totalBytes = 0;
    for (const file of files) {
      if (!isPdfUpload(file)) throw new Error('Only PDF files are allowed.');
      if (Number(file.size || 0) > maxFileSizeBytes) {
        throw new Error(`Each PDF must be ${maxFileSizeMb}MB or smaller.`);
      }
      totalBytes += Number(file.size || 0);
      if (!(await hasPdfHeader(file))) {
        throw new Error('One or more files do not appear to be valid PDF documents.');
      }
    }
    if (totalBytes > maxTotalInputSizeBytes) {
      throw new Error(`Total upload size must be ${maxTotalInputSizeMb}MB or smaller.`);
    }

    const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'myfood-pdf-merge-'));
    const inputPaths = [];
    const outputPath = path.join(tempDir, 'merged.pdf');

    try {
      for (let i = 0; i < files.length; i += 1) {
        const file = files[i];
        const existingPath = resolveInputPathFromFile(file);
        if (existingPath) {
          inputPaths.push(existingPath);
          continue;
        }
        const filenamePart = normalizeTempFilename(file?.originalname, `input-${i + 1}.pdf`);
        const extension = path.extname(filenamePart).toLowerCase() === '.pdf' ? '' : '.pdf';
        const inputPath = path.join(tempDir, `${String(i + 1).padStart(3, '0')}-${filenamePart}${extension}`);
        if (Buffer.isBuffer(file?.buffer)) {
          await fs.promises.writeFile(inputPath, file.buffer);
          inputPaths.push(inputPath);
        }
      }
      if (inputPaths.length < 2) {
        throw new Error('Please select at least 2 PDF files to merge.');
      }
      await runGhostscript([
        '-dSAFER',
        '-dPDFSTOPONERROR',
        '-dBATCH',
        '-dNOPAUSE',
        '-q',
        '-sDEVICE=pdfwrite',
        `-sOutputFile=${outputPath}`,
        ...inputPaths
      ]);
      return fs.promises.readFile(outputPath);
    } finally {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    }
  }

  return {
    key: 'pdf_merge',
    name: 'PDF Merge',
    description: 'Merge multiple PDF files into a single downloadable PDF.',
    inputFieldName: 'pdfs',
    inputLabel: `PDF files (2 to ${maxFiles})`,
    fileAccept: 'application/pdf,.pdf',
    supportsOutputName: true,
    outputNamePlaceholder: 'merged-document.pdf',
    notes: [
      `Each file must be ${maxFileSizeMb}MB or smaller.`,
      `Total upload must be ${maxTotalInputSizeMb}MB or smaller.`
    ],
    submitLabel: 'Merge PDFs',
    maxFiles,
    maxFileSizeMb,
    maxTotalInputSizeMb,
    createUploadMiddleware(multer) {
      const tempUploadDir = path.join(os.tmpdir(), 'myfood-tool-upload');
      fs.mkdirSync(tempUploadDir, { recursive: true });
      return multer({
        storage: multer.diskStorage({
          destination: (_req, _file, cb) => cb(null, tempUploadDir),
          filename: (_req, file, cb) => {
            const base = normalizeTempFilename(file?.originalname, 'upload.pdf');
            cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 10)}-${base}`);
          }
        }),
        limits: {
          files: maxFiles,
          fileSize: maxFileSizeBytes
        }
      }).array('pdfs', maxFiles);
    },
    getMulterErrorMessage(err) {
      if (!err || err.name !== 'MulterError') return null;
      if (err.code === 'LIMIT_FILE_COUNT') return `You can upload up to ${maxFiles} PDF files per merge.`;
      if (err.code === 'LIMIT_FILE_SIZE') return `Each PDF must be ${maxFileSizeMb}MB or smaller.`;
      if (err.code === 'LIMIT_UNEXPECTED_FILE') return 'Unexpected upload field. Use "pdfs" for PDF files.';
      return null;
    },
    isExpectedError(message) {
      return (
        message.includes('Please select at least') ||
        message.includes('Only PDF files') ||
        message.includes('Each PDF must') ||
        message.includes('Total upload size must') ||
        message.includes('do not appear to be valid PDF') ||
        message.includes('timed out') ||
        message.includes('You can upload up to') ||
        message.includes('Ghostscript is not installed')
      );
    },
    async run(context = {}) {
      const files = Array.isArray(context.files) ? context.files : [];
      const body = context.body || {};
      const buffer = await mergePdfFiles(files);
      const filename = normalizeOutputFilename(body.outputName);
      return {
        contentType: 'application/pdf',
        filename,
        buffer,
        auditMeta: {
          toolKey: 'pdf_merge',
          inputCount: files.length,
          outputBytes: buffer.length
        }
      };
    }
  };
}

module.exports = {
  createPdfMergeTool
};
