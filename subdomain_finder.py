#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Listeleyici Araci
Belirtilen domain icin subdomain araması yapir ve sonuçlari dosyaya kaydeder.
"""

import requests
import json
import sys
import os
import subprocess
import platform
from typing import Set, List
from datetime import datetime
import socket
import ssl

class SubdomainFinder:
    """Subdomain bulma ve listeleme araci"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def search_crt_sh(self) -> None:
        """crt.sh üzerinden subdomain ara"""
        try:
            print("[*] crt.sh üzerinden aramalar yapiliyor...")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, headers=self.headers, timeout=15, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            subdomains = name_value.split('\n')
                            for sub in subdomains:
                                sub = sub.strip().lower()
                                if sub and (self.domain in sub or sub.endswith(self.domain)):
                                    self.subdomains.add(sub)
                    print(f"[+] crt.sh: {len(self.subdomains)} subdomain bulundu")
                except json.JSONDecodeError:
                    print(f"[-] crt.sh JSON hatasi")
        except Exception as e:
            print(f"[-] crt.sh hatasi: {e}")
    
    def search_certspotter(self) -> None:
        """Cert Spotter üzerinden subdomain ara"""
        try:
            print("[*] Cert Spotter üzerinden aramalar yapiliyor...")
            url = f"https://certspotter.com/api/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        for entry in data:
                            dns_names = entry.get('dns_names', [])
                            if isinstance(dns_names, list):
                                for name in dns_names:
                                    name = name.strip().lower()
                                    if name and (self.domain in name or name.endswith(self.domain)):
                                        self.subdomains.add(name)
                    print(f"[+] Cert Spotter: {len(self.subdomains)} toplam subdomain")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] Cert Spotter hatasi: {e}")
    
    def search_ssl_certificates(self) -> None:
        """SSL sertifikalarindan subdomain ara"""
        try:
            print("[*] SSL sertifikalarindan aramalar yapiliyor...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert['subject'])
                    if 'commonName' in subject:
                        cn = subject['commonName'].lower()
                        if cn.endswith(self.domain):
                            self.subdomains.add(cn)
                    
                    for sub_alt in cert.get('subjectAltName', []):
                        if sub_alt[0] == 'DNS':
                            name = sub_alt[1].lower()
                            if self.domain in name or name.endswith(self.domain):
                                self.subdomains.add(name)
        except Exception as e:
            print(f"[-] SSL sertifikasi hatasi: {e}")
    
    def search_rapiddns(self) -> None:
        """RapidDNS üzerinden subdomain ara"""
        try:
            print("[*] RapidDNS üzerinden aramalar yapiliyor...")
            url = f"https://dns.bufferover.run/api/v1/query?q={self.domain}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'FDNS_A' in data:
                        for entry in data['FDNS_A']:
                            parts = entry.split(',')
                            if len(parts) >= 1:
                                subdomain = parts[0].lower()
                                if subdomain and (self.domain in subdomain or subdomain.endswith(self.domain)):
                                    self.subdomains.add(subdomain)
                    print(f"[+] RapidDNS: {len(self.subdomains)} toplam subdomain")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] RapidDNS hatasi: {e}")
    
    def verify_subdomain(self, subdomain: str) -> bool:
        """Subdomain DNS kaydini dogrula"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except (socket.gaierror, socket.error):
            return False
    
    def check_http_response(self, subdomain: str) -> str:
        """HTTP yaniti kontrol et"""
        try:
            response = requests.head(f"http://{subdomain}", 
                                   headers=self.headers, 
                                   timeout=5, 
                                   allow_redirects=False)
            return f"HTTP/{response.status_code}"
        except:
            try:
                response = requests.head(f"https://{subdomain}", 
                                       headers=self.headers, 
                                       timeout=5, 
                                       allow_redirects=False,
                                       verify=False)
                return f"HTTPS/{response.status_code}"
            except:
                return "-"
    
    def open_file(self, file_path: str) -> None:
        """Dosyayi isletim sistemine göre ac"""
        try:
            if platform.system() == 'Windows':
                os.startfile(file_path)
            elif platform.system() == 'Darwin':
                subprocess.Popen(['open', file_path])
            else:
                subprocess.Popen(['xdg-open', file_path])
            print(f"[OK] Dosya acildi: {file_path}")
        except Exception as e:
            print(f"[-] Dosya acilamadi: {e}")
    
    def save_results(self, output_file: str = None) -> str:
        """Sonuçlari dosyaya kaydet"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"subdomains_{self.domain}_{timestamp}.txt"
        
        sorted_subdomains = sorted(list(self.subdomains))
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("Subdomain Araştirması Sonuçlari\n")
                f.write("="*80 + "\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Toplam Bulunan: {len(sorted_subdomains)} subdomain\n")
                f.write("="*80 + "\n\n")
                
                f.write("SUBDOMAIN LISTESI:\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'#':<5} {'SUBDOMAIN':<50} {'DURUM':<15} {'HTTP':<10}\n")
                f.write("-" * 80 + "\n")
                
                verified_count = 0
                for idx, subdomain in enumerate(sorted_subdomains, 1):
                    is_active = self.verify_subdomain(subdomain)
                    status = "[AKTIF]" if is_active else "[PASIF]"
                    if is_active:
                        verified_count += 1
                        http_status = self.check_http_response(subdomain)
                    else:
                        http_status = "-"
                    
                    f.write(f"{idx:<5} {subdomain:<50} {status:<15} {http_status:<10}\n")
                
                f.write("\n" + "="*80 + "\n")
                f.write("ÖZET\n")
                f.write("="*80 + "\n")
                f.write(f"Toplam Subdomain: {len(sorted_subdomains)}\n")
                f.write(f"Aktif Subdomain: {verified_count}\n")
                f.write(f"Pasif Subdomain: {len(sorted_subdomains) - verified_count}\n")
                f.write("="*80 + "\n")
            
            return output_file
        except Exception as e:
            print(f"[-] Dosya kaydetme hatasi: {e}")
            return None
    
    def run(self) -> None:
        """Araştirmayi çalistir"""
        print(f"\n[*] '{self.domain}' için subdomain araması başliyor...\n")
        
        self.search_crt_sh()
        self.search_certspotter()
        self.search_ssl_certificates()
        self.search_rapiddns()
        
        print(f"\n[*] Şu ana kadar bulunan: {len(self.subdomains)} benzersiz subdomain\n")
        
        if len(self.subdomains) > 0:
            print(f"[*] Sonuçlar kaydediliyor...\n")
            output_file = self.save_results()
            
            if output_file:
                print(f"[OK] Sonuçlar kaydedildi: {output_file}")
                print(f"[OK] Toplam {len(self.subdomains)} subdomain bulundu")
                print(f"\n[*] Dosya aciliyor...\n")
                self.open_file(output_file)
            else:
                print(f"[HATA] Sonuçlar kaydedilemedi!")
        else:
            print(f"[HATA] Hiç subdomain bulunamadi!")


def print_banner():
    """Banner yazdir"""
    banner = """
    =================================================================
    sAMeTTurk Sub_Scanner #v1.0
    WebGuvenligi Team
    
    Multi-Source Subdomain Discovery Tool
    =================================================================
    """
    print(banner)


def main():
    """Ana program"""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print_banner()
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("\n[?] Domain adi girin (örn: example.com): ").strip()
    
    if not domain:
        print("[-] Domain adi boş olamaz!")
        return
    
    domain = domain.lower().strip()
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    if not domain.count('.') or len(domain) < 3:
        print("[-] Geçerli bir domain girin!")
        return
    
    finder = SubdomainFinder(domain)
    finder.run()


if __name__ == "__main__":
    main()
