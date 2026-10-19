# Instagram data lab (JupyterLite)

A Jupyter environment that students open as a web page. Python runs inside their
browser (Pyodide / WebAssembly), the files they drag in stay in their browser's
storage, and no server ever sees their data. Used in ECOSM 2026 to scan — and later
anonymise — each student's own Instagram data export.

Live site: https://gcapr.github.io/teaching_material_public_folder/instagram-data-lab/
Direct link to the notebook: https://gcapr.github.io/teaching_material_public_folder/instagram-data-lab/lab/index.html?path=01_scan_for_personal_data.ipynb

## What is where

```
instagram-data-lab/
├── content/                         what students see in the file browser
│   ├── README.md                    instructions for students
│   ├── 01_scan_for_personal_data.ipynb
│   └── ig_pii_scan.py               the scanner (standard library only, so it also runs on a laptop)
├── requirements.txt                 build tools (jupyterlite-core, the Pyodide kernel, JupyterLab)
└── jupyter_lite_config.json         build settings
.github/workflows/pages.yml          builds the site on every push to ECOSM-2026 and publishes it
site/index.html                      landing page of the Pages site
```

## How it is published

Every push to the `ECOSM-2026` branch runs the workflow in `.github/workflows/pages.yml`:
it installs the build tools, runs `jupyter lite build` on `content/`, adds the landing page
and the 2025 lab page (copied from the `ECOSM_2025_SciencesPo` branch so its old link keeps
working), and deploys the result to GitHub Pages. Nothing generated is committed.

One-time setting, done once in the repository: **Settings → Pages → Build and deployment →
Source: GitHub Actions**. Until that is set, the deploy step fails with a message pointing
to that page.

## Updating things

- Change the scanner or the notebook: edit the file in `content/`, commit, push. The site
  rebuilds in a couple of minutes (Actions tab shows progress). Students may need a hard
  refresh (Ctrl/Cmd+Shift+R) to see the new version.
- Add a notebook (e.g. the anonymiser or the analysis): drop it in `content/`, push.
- Python packages: anything in the Pyodide distribution (pandas, numpy, matplotlib, scipy,
  scikit-learn, networkx, …) loads on first import; pure-Python packages from PyPI can be
  installed from a cell with `%pip install name`. Packages with compiled extensions that
  are not in Pyodide (spaCy, for instance) are not available.

## Testing locally

```
pip install -r requirements.txt
jupyter lite build            # writes _output/
jupyter lite serve            # opens http://localhost:8000
```

`_output/` and `.jupyterlite.doit.db` are build artefacts and are ignored by git.

## The privacy claim, and how to check it

The page is static: GitHub Pages serves files and cannot execute anything. The Python
interpreter and the packages are downloaded from a CDN as code; students' files are copied
into the browser's own storage (IndexedDB) and never leave the machine, because nothing
in the notebook makes a network request. To demonstrate it in class: open the browser's
Network tab while a scan runs (no uploads), or load the page, go offline, and run it.
