# جرّب Raqib الآن / Try Raqib now

## 1. من المتصفح — جاهز الآن / In the browser — live now

الكونسول يعمل على المنفذ **8787**. افتح رابط المعاينة الحي من الشريط العلوي.

The console is running on port **8787**. Open the live preview from the top bar.

- اكتب مسار أي ملف أو مجلد في المربع العلوي، ثم اضغط **Inspect**.
  Type any file or directory path in the top box, then press **Inspect**.
- أزرار الأنواع (auto / elf / pe / js / chromium / browser / macho / asar /
  map / manifest / strings) تخبرك Raqib كيف يقرأ ما مررته.
- كل نتيجة تحمل «Not proven» — ما هو **مُثبَت** وما هو **مجرد استنتاج**.
  Every report carries a “Not proven” section: what is established, and what
  is only an inference.

## 2. من سطر الأوامر / From the command line

```bash
tar -xzf raqib-0.2.0-linux-x64.tar.gz
cd raqib-0.2.0-linux-x64
sha256sum -c SHA256SUMS          # يتحقق من سلامة الحزمة / verifies the bundle
node raqib.mjs --help             # كل الأوامر / every command
```

جرّب هذه الأوامر على جهازك / Try these on your own machine:

```bash
# ما هذا الملف التنفيذي؟ / What is this executable?
node raqib.mjs analyze /usr/bin/ls

# ما الذي يوجد داخل مجلد تثبيت متصفح؟ / What is inside a browser install?
node raqib.mjs analyze /opt/google/chrome

# من أين جاء هذا السطر في الحزمة المغلّقة؟ / Where did this line come from?
node raqib.mjs map ./dist/bundle.js --line 10 --column 20

# ما الفرق بين نسختين؟ / What changed between two builds?
node raqib.mjs compare ./old-app ./new-app

# ما الذي يعلنه ملف package.json؟ / What does the manifest declare?
node raqib.mjs manifest ./app/package.json

# ابحث داخل شجرة / Search inside a tree
node raqib.mjs search ./src "contextBridge" --context 2
```

## 3. من وكيلك / From your agent

التسجيل **محلي بالكامل** — لا يُنزَّل شيء / The registration is entirely local —
nothing is downloaded:

```bash
node raqib.mjs setup claude    # أو codex / cursor / gemini
```

ثم أعد تشغيل الوكيل. سيظهر لك 11 أداة / Restart the agent. You get 11 tools:

| الأداة / Tool | ماذا تفعل / What it does |
|---|---|
| `inspect_binary` | ELF و PE و Mach-O: أقسام، رموز، استيرادات، أعلام الحماية / sections, symbols, imports, hardening flags |
| `analyze_js_application` | تطبيق JavaScript / Electron / a JavaScript or Electron application |
| `search_code` | بحث في محتوى شجرة / search the contents of a tree |
| `index_tree` | جرد مجلد / inventory a directory tree |
| `inspect_chromium_tree` | خريطة شجرة مصدر Chromium / map a Chromium source tree |
| `identify_browser` | ما نوع المتصفح المثبّت / what kind of browser is installed |
| `read_asar` | قراءة أرشيف `.asar` / read an Electron archive |
| `resolve_source_map` | حل مواضع source map في الاتجاهين / map positions in both directions |
| `compare_analyses` | مقارنة تحليلين / compare two analyses |
| `inspect_manifest` | قراءة `package.json` / read a package manifest |
| `get_evidence` | استرجاع سجل تحليل سابق / retrieve an earlier record |

## لا يحتاج إنترنت / It needs no internet

- لا تتبّع، لا فحوص تحديث، لا مقابس (sockets) — `node raqib.mjs doctor` يقرّ بذلك.
  No telemetry, no update checks, no sockets — `raqib doctor` says so out loud.
- الخطوط الثلاثة مضمّنة داخل الملف الواحد بصيغة base64.
  The three typefaces are embedded in the single file as base64.
- `raqib.mjs` هو كل شيء: لا `npm install`، لا خطوة بناء، Node ≥ 20.11 فقط.
  `raqib.mjs` is everything: no `npm install`, no build step, only Node ≥ 20.11.

## مع Brave / Chromium

```bash
node raqib.mjs chromium ~/src/brave-core      # خريطة شجرة Chromium / map a Chromium tree
node raqib.mjs browser /usr/lib/brave-browser  # هوية المتصفح / identify the browser
```
