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

## 2-ب. على ويندوز / On Windows

الحزمة نفسها تعمل على ويندوز بلا أي تعديل — الملف `raqib.mjs` هو JavaScript
وليست ملفاً تنفيذياً مُصرَّفاً، فهو واحد على كل الأنظمة.

The same bundle runs on Windows unchanged: `raqib.mjs` is JavaScript, not a
compiled executable, and it is one file for every operating system.

**1. نزّل الحزمة** — `raqib-0.2.0-windows.zip` (صُنع خصيصاً لويندوز، لأن
ويندوز فيه فكّ ضغط zip مدمج بينما tar.gz يحتاج أداة خارجية).

Download `raqib-0.2.0-windows.zip` — built for Windows, which has a built-in
unzip while `.tar.gz` needs an extra tool.

**2. افتحها** بنقرة يمين ← *Extract All*، أو من PowerShell:

```powershell
Expand-Archive -Path raqib-0.2.0-windows.zip -DestinationPath raqib
cd raqib\raqib-0.2.0-windows
```

**3. شغّلها:**

```powershell
node raqib.mjs --help
node raqib.mjs doctor
```

أو استخدم المشغّل المرفق `raqib.cmd` الذي يتيح لك كتابة `raqib` بدل `node raqib.mjs`:

```powershell
.\raqib.cmd analyze C:\\Windows\\System32\\notepad.exe
.\raqib.cmd browser "C:\\Program Files\\BraveSoftware\\Brave-Browser"
```

**4. تحقّق من سلامة الملف** — على ويندوز:

```powershell
certutil -hashfile raqib.mjs SHA256
```

وقارن النتيجة مع السطر المقابل في `SHA256SUMS`.

**5. لو لم يكن Node مثبتاً:** نزّل Node 20.11 أو أحدث من nodejs.org، ثبّته،
ثم أعد تشغيل الطرفية. لا شيء آخر مطلوب — لا `npm install`، ولا خطوة بناء.

**6. للوكيل** — التسجيل محلي بالكامل:

```powershell
node raqib.mjs setup claude
```

**ملاحظة عن المسارات:** أدخل المسارات بين علامتي تنصيص إذا احتوت على مسافات،
مثل `"C:\Program Files\BraveSoftware\Brave-Browser"`. Raiqib يتعرّف على
المتصفحات من ملفها التنفيذي مباشرة (يقرأ `Product-String`)، فلا يعتمد على
أسماء المجلدات.

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
