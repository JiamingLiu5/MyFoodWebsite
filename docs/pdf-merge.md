# PDF Merge Tool

Merge multiple PDF files into a single downloadable PDF.

## Usage

1. Navigate to **Tools** (`/tools`)
2. Upload 2 or more PDF files using the file picker
3. Optionally set a custom output filename
4. Click **Merge PDFs**
5. The merged PDF downloads automatically

## Requirements

- [Ghostscript](https://www.ghostscript.com/) must be installed on the server
- Admin must grant tool access to the user via User Management

## Limits

| Limit | Default | Env Variable |
|-------|---------|-------------|
| Max files per merge | 10 | `MAX_TOOL_PDF_FILES` |
| Max file size | 20 MB | `MAX_TOOL_PDF_FILE_SIZE_MB` |
| Max total upload size | 80 MB | `MAX_TOOL_PDF_TOTAL_INPUT_MB` |
| Execution timeout | 45 seconds | `TOOL_RUN_TIMEOUT_SECONDS` |
| Rate limit | 6 runs / 60 seconds | `TOOL_RATE_LIMIT_MAX_RUNS` / `TOOL_RATE_LIMIT_WINDOW_SECONDS` |
| Concurrent runs (global) | 2 | `TOOL_MAX_CONCURRENT_RUNS` |
| Concurrent runs (per tool) | 1 | `TOOL_MAX_CONCURRENT_RUNS_PER_TOOL` |

## Configuration

Add to `.env`:

```env
GHOSTSCRIPT_PATH=gs
MAX_TOOL_PDF_FILES=10
MAX_TOOL_PDF_FILE_SIZE_MB=20
MAX_TOOL_PDF_TOTAL_INPUT_MB=80
TOOL_RUN_TIMEOUT_SECONDS=45
```

## Security

- Files are validated for PDF headers (`%PDF-`) before processing
- MIME type and extension checks (only `application/pdf` / `.pdf` accepted)
- Ghostscript runs with `-dSAFER` flag to prevent file system access
- Temporary files are cleaned up after each run
- CSRF protection on all submissions

## Errors

| Error | Cause |
|-------|-------|
| "Please select at least 2 PDF files to merge" | Fewer than 2 files uploaded |
| "Only PDF files are allowed" | Non-PDF file detected |
| "Each PDF must be 20MB or smaller" | Individual file exceeds size limit |
| "Total upload size must be 80MB or smaller" | Combined files exceed total limit |
| "One or more files do not appear to be valid PDF documents" | File missing PDF header |
| "PDF merge timed out" | Ghostscript exceeded execution timeout |
| "Ghostscript is not installed on this server" | `gs` binary not found |
