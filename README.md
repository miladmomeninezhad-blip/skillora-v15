# Skillora v15

Skillora v15 ادامه مستقیم Skillora v14 است و همان Node.js + Express + SQLite را حفظ می‌کند.

## امکانات v15
- ثبت‌نام و ورود واقعی
- نقش مشتری و فریلنسر
- پروفایل
- ثبت و نمایش پروژه
- ارسال پیشنهاد فریلنسر
- پنل ساده پیشنهادهای هر پروژه برای مشتری
- انتخاب فریلنسر توسط مشتری
- رد خودکار پیشنهادهای دیگر هنگام انتخاب
- تغییر وضعیت پروژه به `in_progress` و `completed`
- احراز هویت JWT در HttpOnly cookie

## اجرا
Node.js 20+

```bash
npm install
cp .env.example .env
npm start
```

سپس `http://localhost:3000` را باز کنید.

> پرداخت واقعی، پیام‌رسانی، اعلان‌ها و سخت‌سازی کامل برای انتشار عمومی هنوز در این نسخه فعال نیستند.


## Deploy روی Render
Repository باید مستقیماً شامل package.json، backend/، frontend/ و database/ باشد.
Build command: `npm install`
Start command: `npm start`
