# Demo 01 — Basic triage: catch the disguised executable

A user received a batch of files and dropped them in `samples/`. The
extensions look harmless, but extensions lie. MAGICID reads the real
leading bytes (magic numbers) and tells you what each file *actually* is.

## The sample set (`samples/`)

| File                  | Looks like | Truly is              | Why it matters |
|-----------------------|------------|-----------------------|----------------|
| `vacation_photo.jpg`  | a JPEG     | **Windows PE (`MZ`)** | executable smuggled behind `.jpg` -> **HIGH** |
| `report.docx`         | a Word doc | **PDF (`%PDF-`)**     | mislabeled document -> **MEDIUM** |
| `logo.png`            | a PNG      | PNG                   | consistent -> **OK** |
| `backup.gz`           | gzip       | gzip                  | consistent -> **OK** |
| `mystery.dat`         | unknown    | unknown magic         | unrecognized -> **LOW** |

## Run it

Human-readable table:

```bash
python -m magicid scan demos/01-basic/samples -r
```

Machine-readable JSON for a pipeline:

```bash
python -m magicid scan demos/01-basic/samples -r --format json
```

Shareable self-contained HTML report (the tool's UI):

```bash
python -m magicid scan demos/01-basic/samples -r --format html --out report.html
```

## Expected outcome

- `vacation_photo.jpg` is flagged **HIGH** — a `.jpg` whose bytes are a
  Windows PE executable (the classic payload-smuggling trick).
- `report.docx` is flagged **MEDIUM** — true type PDF, wrong extension.
- `logo.png` and `backup.gz` are **OK**.
- `mystery.dat` is **LOW** (unknown magic).
- Exit code is **1** because findings exist (good for CI / triage gates).

This is detection / triage only: MAGICID reads bytes and reports the true
type. It performs no network calls and takes no action against any system.
