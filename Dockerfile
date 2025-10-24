# استخدم صورة بايثون الرسمية كصورة أساسية
FROM python:3.10-slim

# تعيين دليل العمل داخل الحاوية
WORKDIR /app

# نسخ ملفات المتطلبات وتثبيتها أولاً (لتحسين التخزين المؤقت لـ Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات التطبيق
COPY . .

# تعرض الحاوية المنفذ 5000 (الافتراضي لـ Flask)
EXPOSE 5000

# أمر التشغيل (مماثل لـ Procfile ولكن يعمل داخل Docker)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
