<img width="2227" height="1536" alt="Gemini_Generated_Image_9dwwhw9dwwhw9dww" src="https://github.com/user-attachments/assets/c3da9709-8225-4248-80eb-ada6e561ae35" />


سكربت برمجي مؤتمت مخصص لمحترفي الأمن السيبراني لتنفيذ عمليات الاستطلاع وجمع المعلومات واكتشاف الثغرات.

## الميزات
- تعداد النطاقات الفرعية.
- الفحص الحي لخدمات الويب.
- الزحف واكتشاف المسارات.
- الفحص الآلي للثغرات عبر قوالب Nuclei.
- التخمين الموجه للمسارات (Directory Fuzzing).

## المتطلبات المسبقة
يجب تثبيت الأدوات التالية وتواجدها في مسار النظام (`PATH`):
- subfinder
- dnsx
- httpx
- katana
- nuclei
- ffuf

## الاستخدام
```bash
chmod +x bb_workflow.py
./bb_workflow.py -d target.com -w /path/to/wordlist.txt
