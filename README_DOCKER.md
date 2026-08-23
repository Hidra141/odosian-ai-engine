# ODOSIAN AI Engine - Docker Guide / دليل تشغيل دوكر

هذا الدليل يشرح كيفية بناء وتشغيل محرك **ODOSIAN AI Engine** باستخدام Docker و Docker Compose، وكيفية إرسال واستلام المشروع بين أفراد الفريق.

---

## 1. البناء التشغيلي الخفيف (Quick Start)

### استخدام Docker Compose (الطريقة الأسهل)
```bash
# بناء وتفقد الصورة وإجراء الاختبارات
docker compose up --build
```

### استخدام Docker مباشرة
```bash
# 1. بناء صورة دوكر
docker build -t odosian-ai-engine .

# 2. تشغيل الحاوية وإجراء الاختبارات
docker run --rm -it odosian-ai-engine pytest

# 3. تشغيل الحاوية وتمرير ملف البيئة والسرية (.env)
docker run --rm -it --env-file .env odosian-ai-engine
```

---

## 2. كيفية مشاركة المشروع مع زميلك (How to Share with a Colleague)

توجد طريقتان لمشاركة المشروع مع زميلك:

### الخيار الأول: إرسال السورس كود (الموصى به 🌟)
1. قم بضغط مجلد المشروع بأكمله إلى ملف ZIP (الملفات مثل `.venv` و `.env` مستبعدة تلقائياً عبر `.dockerignore`).
2. قم بإرسال الملف المضغوط إلى زميلك.
3. يقوم زميلك بفك الضغط وتنفيذ الأمر التالي لبناء وتشغيل المشروع فوراً:
   ```bash
   cp .env.example .env   # وضع مفتاح API Key في ملف .env
   docker compose up --build
   ```

### الخيار الثاني: تصدير صورة Docker جاهزة كملف Tar
إذا لم يكن لدى زميلك اتصال إنترنت قوي لبناء الصورة وتنزيل المكتبات:
1. قم بتصدير صورة الدوكر الجاهزة لديك إلى ملف `.tar`:
   ```bash
   docker save -o odosian-ai-engine.tar odosian-ai-engine:latest
   ```
2. أرسل ملف `odosian-ai-engine.tar` لزميلك.
3. يقوم زميلك باستيراد الصورة وتشغيلها بدون الحاجة لبنائها:
   ```bash
   # استيراد الصورة
   docker load -i odosian-ai-engine.tar

   # تشغيل الاختبارات من الصورة المستوردة
   docker run --rm -it odosian-ai-engine:latest pytest
   ```

---

## 3. الهيكلية التقنية للحاوية (Technical Details)
- **Base Image:** `python:3.12-slim`
- **Working Dir:** `/app`
- **Security:** تم استبعاد الملفات الحساسة وحسابات المفاتيح عبر `.dockerignore`.
