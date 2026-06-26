#!/usr/bin/env python3
import os
import sys
import time
import threading
import subprocess
import argparse
import shutil

class Spinner:
    def __init__(self, message="قيد التنفيذ..."):
        self.spinner_chars = ['|', '/', '-', '\\']
        self.delay = 0.1
        self.busy = False
        self.message = message

    def spinner_task(self):
        i = 0
        while self.busy:
            sys.stdout.write(f"\r[{self.spinner_chars[i]}] {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i = (i + 1) % len(self.spinner_chars)
        sys.stdout.write('\r' + ' ' * (len(self.message) + 5) + '\r')

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        self.busy = False
        time.sleep(self.delay)

def check_tools(tools):
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        print(f"[!] الأدوات التالية غير مثبتة أو غير موجودة في المسار (PATH): {', '.join(missing)}")
        sys.exit(1)

def run_command(command, output_file, message):
    spinner = Spinner(message)
    spinner.start()
    try:
        with open(output_file, "w") as out:
            subprocess.run(command, shell=True, stdout=out, stderr=subprocess.DEVNULL, check=True)
        spinner.stop()
        print(f"[+] اكتمل: {message} -> {output_file}")
    except subprocess.CalledProcessError:
        spinner.stop()
        print(f"[-] فشل: {message}")

def extract_parameters(input_file, output_file):
    spinner = Spinner("استخراج الروابط التي تحتوي على معلمات (Parameters)...")
    spinner.start()
    params = set()
    if os.path.exists(input_file):
        with open(input_file, "r") as f:
            for line in f:
                if "=" in line:
                    params.add(line.strip())
    with open(output_file, "w") as f:
        for p in sorted(params):
            f.write(p + "\n")
    spinner.stop()
    print(f"[+] اكتمل: استخراج المعلمات -> {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Web Application Bug Bounty Workflow - Python Edition")
    parser.add_argument("-d", "--domain", required=True, help="النطاق المستهدف (مثال: example.com)")
    parser.add_argument("-w", "--wordlist", default="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt", help="مسار قائمة الكلمات لـ ffuf")
    args = parser.parse_args()

    target = args.domain
    wordlist = args.wordlist

    required_tools = ["subfinder", "dnsx", "httpx", "katana", "nuclei", "ffuf"]
    check_tools(required_tools)

    if not os.path.exists(wordlist):
        print(f"[!] قائمة الكلمات غير موجودة: {wordlist}")
        sys.exit(1)

    work_dir = f"{target}_recon"
    os.makedirs(work_dir, exist_ok=True)
    
    subdomains_file = os.path.join(work_dir, "1_subdomains.txt")
    resolved_file = os.path.join(work_dir, "2_resolved.txt")
    alive_file = os.path.join(work_dir, "3_alive.txt")
    urls_file = os.path.join(work_dir, "4_urls.txt")
    params_file = os.path.join(work_dir, "5_params.txt")
    nuclei_hosts_file = os.path.join(work_dir, "6_nuclei_hosts.txt")
    nuclei_urls_file = os.path.join(work_dir, "7_nuclei_urls.txt")

    print(f"[*] بدء فحص النطاق: {target}")
    print(f"[*] مجلد العمل: {work_dir}\n")

    # 1. Subdomain Enumeration
    run_command(f"subfinder -d {target} -all -silent", subdomains_file, "تعداد النطاقات الفرعية (subfinder)")

    # 2. DNS Resolution
    run_command(f"dnsx -l {subdomains_file} -silent", resolved_file, "تصفية النطاقات الحية عبر DNS (dnsx)")

    # 3. Web Probing
    run_command(f"httpx -l {resolved_file} -silent", alive_file, "فحص خدمات الويب النشطة (httpx)")

    # 4. Crawling
    run_command(f"katana -list {alive_file} -silent -jc -d 3", urls_file, "الزحف واكتشاف المسارات (katana)")

    # 5. Parameter Extraction
    extract_parameters(urls_file, params_file)

    # 6. Nuclei Host-Based Scan
    run_command(f"nuclei -l {alive_file} -t cves/,misconfiguration/,exposures/ -severity low,medium,high,critical -silent", nuclei_hosts_file, "فحص ثغرات البنية التحتية (nuclei - hosts)")

    # 7. Nuclei Endpoint-Based Scan
    run_command(f"nuclei -l {urls_file} -tags xss,sqli,lfi,ssrf -severity medium,high,critical -silent", nuclei_urls_file, "فحص ثغرات المسارات (nuclei - urls)")

    # 8. Directory Fuzzing
    print(f"[*] بدء التخمين الموجه للمسارات المخفية (ffuf) على الأهداف الحية...")
    if os.path.exists(alive_file):
        with open(alive_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        
        for t in targets:
            safe_name = t.replace("https://", "").replace("http://", "").replace("/", "_")
            out_csv = os.path.join(work_dir, f"8_ffuf_{safe_name}.csv")
            cmd = f"ffuf -w {wordlist} -u {t}/FUZZ -mc 200,301,403,500 -silent -of csv -o {out_csv}"
            run_command(cmd, out_csv, f"تخمين المسارات على {t}")
    
    print("\n[*] اكتملت عملية الفحص. النتائج محفوظة في المجلد المخصص.")

if __name__ == "__main__":
    main()
