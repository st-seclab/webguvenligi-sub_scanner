#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Listeleyici Aracı
Belirtilen domain için subdomain araması yapır ve sonuçları dosyaya kaydeder.
"""

import requests
import json
import sys
from typing import Set, List
from datetime import datetime
import socket
import ssl
import re

class SubdomainFinder:
    """Subdomain bulma ve listeleme aracı"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def search_crt_sh(self) -> None:
        """crt.sh üzerinden subdomain ara"""
        try:
            print("[*] crt.sh üzerinden aramalar yapılıyor...")
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
                    print(f"[-] crt.sh JSON hatası")
        except Exception as e:
            print(f"[-] crt.sh hatası: {e}")
    
    def search_certspotter(self) -> None:
        """Cert Spotter üzerinden subdomain ara"""
        try:
            print("[*] Cert Spotter üzerinden aramalar yapılıyor...")
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
            print(f"[-] Cert Spotter hatası: {e}")
    
    def search_ssl_certificates(self) -> None:
        """SSL sertifikalarından subdomain ara"""
        try:
            print("[*] SSL sertifikalarından aramalar yapılıyor...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Subject CN'den
                    subject = dict(x[0] for x in cert['subject'])
                    if 'commonName' in subject:
                        cn = subject['commonName'].lower()
                        if cn.endswith(self.domain):
                            self.subdomains.add(cn)
                    
                    # SAN'dan
                    for sub_alt in cert.get('subjectAltName', []):
                        if sub_alt[0] == 'DNS':
                            name = sub_alt[1].lower()
                            if self.domain in name or name.endswith(self.domain):
                                self.subdomains.add(name)
        except Exception as e:
            print(f"[-] SSL sertifikası hatası: {e}")
    
    def search_securitytrails(self) -> None:
        """SecurityTrails üzerinden subdomain ara (ücretsiz endpoint)"""
        try:
            print("[*] SecurityTrails üzerinden aramalar yapılıyor...")
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'subdomains' in data:
                        for sub in data['subdomains']:
                            full_domain = f"{sub}.{self.domain}".lower()
                            self.subdomains.add(full_domain)
                    print(f"[+] SecurityTrails: {len(self.subdomains)} toplam subdomain")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] SecurityTrails hatası: {e}")
    
    def search_rapiddns(self) -> None:
        """RapidDNS üzerinden subdomain ara"""
        try:
            print("[*] RapidDNS üzerinden aramalar yapılıyor...")
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
            print(f"[-] RapidDNS hatası: {e}")
    
    def verify_subdomain(self, subdomain: str) -> bool:
        """Subdomain DNS kaydını doğrula"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except (socket.gaierror, socket.error):
            return False
    
    def check_http_response(self, subdomain: str) -> str:
        """HTTP yanıtı kontrol et"""
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
    
    def save_results(self, output_file: str = None) -> str:
        """Sonuçları dosyaya kaydet"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"subdomains_{self.domain}_{timestamp}.txt"
        
        sorted_subdomains = sorted(list(self.subdomains))
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"{'='*80}\n")
                f.write(f"Subdomain Araştırması Sonuçları\n")
                f.write(f"{'='*80}\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Toplam Bulunan: {len(sorted_subdomains)} subdomain\n")
                f.write(f"{'='*80}\n\n")
                
                f.write("SUBDOMAIN LİSTESİ:\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'#':<5} {'SUBDOMAIN':<50} {'DURUM':<15} {'HTTP':<10}\n")
                f.write("-" * 80 + "\n")
                
                verified_count = 0
                for idx, subdomain in enumerate(sorted_subdomains, 1):
                    is_active = self.verify_subdomain(subdomain)
                    status = "✓ Aktif" if is_active else "✗ Pasif"
                    if is_active:
                        verified_count += 1
                        http_status = self.check_http_response(subdomain)
                    else:
                        http_status = "-"
                    
                    f.write(f"{idx:<5} {subdomain:<50} {status:<15} {http_status:<10}\n")
                
                f.write("\n" + "="*80 + "\n")
                f.write(f"ÖZET\n")
                f.write("="*80 + "\n")
                f.write(f"Toplam Subdomain: {len(sorted_subdomains)}\n")
                f.write(f"Aktif Subdomain: {verified_count}\n")
                f.write(f"Pasif Subdomain: {len(sorted_subdomains) - verified_count}\n")
                f.write("="*80 + "\n")
            
            return output_file
        except Exception as e:
            print(f"[-] Dosya kaydetme hatası: {e}")
            return None
    
    def run(self) -> None:
        """Araştırmayı çalıştır"""
        print(f"\n[*] '{self.domain}' için subdomain araması başlıyor...\n")
        
        self.search_crt_sh()
        self.search_certspotter()
        self.search_ssl_certificates()
        self.search_rapiddns()
        
        print(f"\n[*] Şu ana kadar bulunan: {len(self.subdomains)} benzersiz subdomain\n")
        
        if len(self.subdomains) > 0:
            print(f"[*] Sonuçlar kaydediliyor...\n")
            output_file = self.save_results()
            
            if output_file:
                print(f"[✓] Sonuçlar kaydedildi: {output_file}")
                print(f"[✓] Toplam {len(self.subdomains)} subdomain bulundu")
            else:
                print(f"[-] Sonuçlar kaydedilemedi!")
        else:
            print(f"[-] Hiç subdomain bulunamadı!")


def print_banner():
    """Banner yazdır"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║     sAMeTTurk Sub_Scanner #v1.0                            ║
    ║     WebGuvenligi Team                                      ║
    ║                                                            ║
    ║     Multi-Source Subdomain Discovery Tool                 ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Ana program"""
    # SSL uyarılarını bastır
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print_banner()
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("\n[?] Domain adı girin (örn: example.com): ").strip()
    
    if not domain:
        print("[-] Domain adı boş olamaz!")
        return
    
    # Domain doğrulaması
    domain = domain.lower().strip()
    
    # www. varsa kaldır
    if domain.startswith('www.'):
        domain = domain[4:]
    
    if not domain.count('.') or len(domain) < 3:
        print("[-] Geçerli bir domain girin!")
        return
    
    finder = SubdomainFinder(domain)
    finder.run()


if __name__ == "__main__":
    main()
