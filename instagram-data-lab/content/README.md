# Instagram data lab — read me first

This page is a Jupyter notebook that runs **entirely inside your browser**.
There is no server behind it: the Python interpreter was downloaded into this tab,
and any file you drag in is kept in your browser's local storage on your own computer.
Nothing you upload here is sent anywhere. You can verify this yourself: once the
page has loaded, switch off Wi-Fi — everything keeps working.

## 1. Get your Instagram data

1. In Instagram: *Settings → Accounts Center → Your information and permissions →
   Download your information → Download or transfer information*.
2. Choose **your Instagram account**, then **All available information** (or at least
   *Personal information*, *Connections* and *Your Instagram activity*).
3. Set **Format: JSON**, **Date range: All time**, **Media quality: Low** — or deselect
   media entirely. Photos and videos are not needed and only make the file huge.
4. Meta e-mails you when the export is ready (usually within a day). Download the
   `.zip` file(s) to your computer. Do not unzip them.

## 2. Scan it

1. Drag the `instagram-….zip` file into the file browser on the left of this page
   (or use the upload button ⬆ at the top of the file browser).
2. Open `01_scan_for_personal_data.ipynb` and run the cells top to bottom (Shift+Enter).
3. Read the summary. Everything on screen is masked; the full details are written to the
   `report/` folder, which stays in your browser.
4. Right-click `report.zip` in the file browser → **Download** to keep a copy.

## 3. Anonymise it

1. Open `02_anonymise.ipynb` and run the cells. The default keeps no message text at all
   but keeps what the platform did with you (ads shown, inferred interests, advertisers
   holding your data, apps reporting to Meta); the notebook explains the options and shows
   you the names that will stay visible before you pack the result.
2. The report ends with a re-scan of the output by the same scanner: it should find
   **0 HIGH** items and only pseudonyms.
3. Right-click `anonymised.zip` → **Download**. This is the copy that can leave your
   computer (for the analysis notebooks, Colab, a classmate…). `pseudonym_map.csv` links
   pseudonyms back to real people: it is not in the zip, keep it private or delete it.

## 4. Clean up

When you are done, right-click the raw zip, `report/`, `anonymised/` and the zips →
**Delete**, or clear this site's data in your browser settings. Nothing was uploaded, but
there is no reason to leave the files in the browser either.

## Notes

- Large exports (hundreds of MB) can take a minute to upload into the browser and to scan.
- Browser storage belongs to this browser on this computer: use the same one next time,
  or re-upload the zip.
- Both tools work on a laptop without a browser: download `ig_pii_scan.py` and
  `ig_anonymise.py` into the same folder and run
  `python ig_pii_scan.py instagram-….zip -o report` and
  `python ig_anonymise.py instagram-….zip -o anonymised --zip`.
