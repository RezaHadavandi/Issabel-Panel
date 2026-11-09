# راهنمای نصب پنل ایزابل (نسخه ۲)

## ۱) ساخت کاربر AMI در ایزابل
فایل `/etc/asterisk/manager_custom.conf` را ویرایش کنید:
```
[panel]
secret = یک-رمز-قوی
deny = 0.0.0.0/0.0.0.0
permit = 127.0.0.1/255.255.255.255      ; اگر پنل روی سرور دیگری است، IP همان سرور
read = system,call,agent,user,reporting
write = system,call,agent,user,originate,reporting
```
سپس: `asterisk -rx "manager reload"` ؛ و پورت 5038 را فقط به IP پنل باز کنید (فایروال).

## ۲) نصب با یک خط (لینوکس + داکر)
کد را یک‌بار در گیت‌هاب/گیت‌لب خودتان (ترجیحاً Private) بگذارید، `YOUR_USER` را در `install.sh` عوض کنید، سپس روی سرور:
```
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/issabel-panel/main/install.sh | sudo AMI_USER=panel AMI_PASS='رمز-AMI' bash
```
یا بدون گیت: پوشه را کپی کنید و `sudo ./install.sh` بزنید. اسکریپت داکر را نصب، رازها را تصادفی تولید و پنل را اجرا می‌کند و **رمز اولیه‌ی مدیر** را چاپ می‌کند (همان لحظه عوضش کنید). آدرس: `http://IP:3000`

> اگر ایزابل شما از PJSIP استفاده می‌کند در `.env` مقدار `PEER_TECH=PJSIP` بگذارید و `docker compose up -d` بزنید.

## ۳) نظرسنجی بعد از تماس (دایال‌پلن)
مقدار `HOOK_SECRET` را از `.env` بردارید. در `/etc/asterisk/extensions_custom.conf`:
```
[panel-survey]
exten => s,1,GotoIf($["${QUEUESTATUS}"!="CONTINUE"]?end)
 same => n,Answer()
 same => n,Wait(1)
 same => n,Set(AGEXT=${FILTER(0-9,${CURL(http://127.0.0.1:3000/hook/agent,secret=HOOK_SECRET&uid=${UNIQUEID})})})
 same => n,Playback(custom/panel-agent-intro)
 same => n,Set(I=0)
 same => n,While($[${I}<${LEN(${AGEXT})}])
 same => n,Playback(custom/panel-digit-${AGEXT:${I}:1})
 same => n,Set(I=$[${I}+1])
 same => n,EndWhile
 same => n,Read(SC,custom/panel-survey-prompt,1,,1,6)
 same => n,Playback(custom/panel-thanks)
 same => n,Set(R=${CURL(http://127.0.0.1:3000/hook/call,secret=HOOK_SECRET&uid=${UNIQUEID}&caller=${CALLERID(num)}&dur=${CDR(billsec)}&score=${SC})})
 same => n(end),Hangup()
```
- **مهم:** در ایزابل برای هر صف، در «Queue Options» حرف **`c`** را اضافه کنید (Continue in dialplan if the callee hangs up). بدون آن، با قطع اپراتور تماس مشتری هم قطع می‌شود و نظرسنجی اجرا نمی‌شود. (آزمایش‌شده روی Asterisk 20: بدون `c` مرحله‌ی نظرسنجی اصلاً اجرا نمی‌شد.)
- فایل‌های صوتی را از تب «صداها» بارگذاری کنید (بخش ۷). اگر فایلی بارگذاری نشده، خطی که آن را پخش می‌کند حذف کنید.
- در ایزابل: Admin → Custom Destinations مقدار `panel-survey,s,1` را بسازید و در هر صف به‌عنوان **Failover Destination** بگذارید و Apply Config بزنید.
- اگر **مشتری اول قطع کند** نظرسنجی اجرا نمی‌شود، اما تماس (با صف و اپراتور) و پیامک از رویداد `AgentComplete` ثبت می‌شود؛ پس کاربر AMI باید `read=agent` داشته باشد (در بخش ۱ هست).
- اگر پنل روی سرور دیگری است، `HOOK_ALLOW` را در `.env` با IP آسترسک تنظیم کنید.

## ۴) پنل پیامک
مدیر → «مدیریت سرور» → پنل پیامک: آدرس API، متد، هدر (کلید API)، قالب بدنه با `{to}` `{text}` `{from}`، خطوط ارسال و متن پیام را بدهید و «ارسال تست» بزنید. مثال: `{"to":"{to}","from":"{from}","text":"{text}"}`. فقط HTTPS و آدرس‌های عمومی مجازند؛ برای پنل پیامک داخل شبکه `ALLOW_PRIVATE_SMS=1` و در صورت نیاز `ALLOW_HTTP_SMS=1` را در `.env` بگذارید.

## ۵) نقش‌ها
| نقش | دسترسی |
|---|---|
| مدیر | همه‌چیز: کاربران، واحدها، سرور، پیامک، گزارش‌ها |
| سرپرست | ساخت واحد و اپراتور برای واحدهای خودش؛ کنترل صف، تماس و گزارش همان اپراتورها |
| اپراتور | فقط ورود/خروج و استراحت خودش در صف‌ها (سوییچ گرافیکی) و گزارش خودش |
| ناظر | فقط گزارش‌ها و تاریخچه (کامل، فقط‌خواندنی) |

برای اپراتور و سرپرست حتماً «داخلی» را هنگام ساخت کاربر وارد کنید.

## ۶) امنیت (قبل از استفاده‌ی واقعی)
1. پنل را پشت HTTPS بگذارید (مثلاً Caddy: `caddy reverse-proxy --from panel.example.com --to 127.0.0.1:3000`) و در `.env`: `COOKIE_SECURE=1`، `TRUST_PROXY=1`، `BIND=127.0.0.1`. سپس `docker compose up -d`.
2. دسترسی به پورت پنل و AMI را با فایروال یا VPN محدود کنید.
3. پشتیبان: `docker run --rm -v issabel-panel_panel-data:/d -v $PWD:/b busybox tar czf /b/panel-backup.tgz /d` (نام ولوم ممکن است بسته به نام پوشه فرق کند).
4. به‌روزرسانی: `git pull && docker compose up -d --build`.
5. رمز اولیه‌ی admin را عوض و `.env` را فقط برای root قابل‌خواندن نگه دارید (`chmod 600`).

## ۷) بخش‌های نسخه‌ی ۲.۱
**سازگاری:** پنل با Asterisk 1.8 تا 21 کار می‌کند؛ SIP و PJSIP هم‌زمان خوانده می‌شوند. نسخه‌ی آسترسک در «مدیریت سرور» نمایش داده می‌شود.

**صداها:** پوشه‌ی صداهای آسترسک داخل کانتینر مانت می‌شود. روی هاست یک‌بار اجرا کنید:
```
mkdir -p /var/lib/asterisk/sounds/custom && setfacl -m u:1000:rwx /var/lib/asterisk/sounds/custom && setfacl -m u:asterisk:rx /var/lib/asterisk/sounds/custom
```
فایل‌ها با نام `panel-<مورد>.wav` ذخیره می‌شوند (مثل `custom/panel-survey-prompt`). فایل باید WAV تک‌کاناله 16-bit، 8000 یا 16000 هرتز باشد (تبدیل: `ffmpeg -i in.mp3 -ar 8000 -ac 1 -sample_fmt s16 out.wav`).

**CRM Dynamics 365 (فقط‌خواندنی):**
1. در Azure AD یک App Registration بسازید، Client Secret بگیرید.
2. در Power Platform Admin Center آن را به‌عنوان Application User به محیط اضافه کنید و نقش امنیتی **فقط خواندن (Read)** روی جدول Contact بدهید.
3. در پنل: مدیریت سرور → CRM: آدرس محیط، Tenant ID، Client ID و Secret را وارد و «آزمایش اتصال» بزنید.
جستجوی شماره بر پایه‌ی ۱۰ رقم آخر روی mobilephone/telephone1/telephone2 است؛ شماره‌ها در CRM بهتر است بدون فاصله ذخیره شوند.

**تلفن‌های Grandstream:** در خود تلفن دسترسی وب/API را فعال کنید، سپس در تب «تلفن‌ها» با IP و رمز ادمین تلفن اضافه کنید. مسیرهای API بر پایه‌ی مستند HTTP API گرنداستریم نوشته شده و بسته به مدل/فریمور باید روی یک دستگاه آزمایش شود.

**نکته‌ی مسیر صداها:** در ایزابل/FreePBX مسیر صداها `/var/lib/asterisk/sounds` است. در Debian/Ubuntu مسیر استاندارد `/usr/share/asterisk/sounds` است؛ پوشه‌ی `custom` را به آن لینک کنید (`ln -s /var/lib/asterisk/sounds/custom /usr/share/asterisk/sounds/custom`). اگر فایل پرامپت پیدا نشود، `Read` فوراً با ERROR تمام می‌شود و نظرسنجی بی‌صدا رد می‌شود.

**FreeSWITCH:** پنل فقط با AMI آسترسک کار می‌کند. اگر به پورت ESL فری‌سوییچ وصل شود پیام «AMI آسترسک نیست» نشان داده می‌شود. پشتیبانی از FreeSWITCH نیاز به یک آداپتور جدا (Event Socket) دارد و در نسخه‌ی بعد قابل اضافه شدن است.
