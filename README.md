# Skillora v15

Skillora v15 ادامه مستقیم Skillora v14 است و همان Node.js + Express + SQLite را حفظ می‌کند.

## امکانات v15
- ثبت‌نام و ورود واقعی
- نقش مشتری و فریلنسر
- پروفایل
- ثبت و نمایش پروژه
- ارسال پیشنهاد فریلنسر
- مشاهده پیشنهادهای هر پروژه برای مشتری
- انتخاب فریلنسر توسط مشتری
- رد خودکار پیشنهادهای دیگر هنگام انتخاب
- تغییر وضعیت پروژه به `in_progress` و `completed`
- احراز هویت JWT در HttpOnly cookie
- endpoint سلامت `/api/health` برای بررسی Deploy

## اجرا
Node.js 20+

```bash
npm install
cp .env.example .env
npm start
```

سپس `http://localhost:3000` را باز کنید.

## Deploy روی Render
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check: `/api/health`
- `JWT_SECRET` به‌صورت Secret تولیدشده توسط Render تنظیم می‌شود.

> این نسخه برای تست و نمونه اولیه است. Render Free فایل‌سیستم محلی را پایدار نگه نمی‌دارد؛ بنابراین SQLite برای تست مناسب است و برای استفاده واقعی باید دیتابیس پایدار مثل Postgres اضافه شود.
> پرداخت واقعی، پیام‌رسانی، اعلان‌ها و سخت‌سازی کامل برای انتشار عمومی هنوز در این نسخه فعال نیستند.
