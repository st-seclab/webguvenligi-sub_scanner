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
from urllib.parse import urlparse
import socket

class SubdomainFinder:
    """Subdomain bulma ve listeleme aracı"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.found_count = 0
        
    def search_crt_sh(self) -> None:
        """crt.sh üzerinden subdomain ara"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        subdomains = name_value.split('\n')
                        for sub in subdomains:
                            sub = sub.strip()
                            if sub and self.domain in sub:
                                self.subdomains.add(sub)
                    print(f"[+] crt.sh: {len(self.subdomains)} subdomain bulundu")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"[-] crt.sh hatası: {e}")
    
    def search_dnsdumpster(self) -> None:
        """DNS Dumpster üzerinden subdomain ara"""
        try:
            url = f"https://dnsdumpster.com/api/v3/dns/lookup/{self.domain}/"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'subdomains' in data:
                        for sub in data['subdomains']:
                            if isinstance(sub, dict):
                                subdomain = sub.get('domain', '')
                            else:
                                subdomain = str(sub)
                            if subdomain and self.domain in subdomain:
                                self.subdomains.add(subdomain)
                    print(f"[+] DNS Dumpster: {len(self.subdomains)} toplam subdomain")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"[-] DNS Dumpster hatası: {e}")
    
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
            return f"{response.status_code}"
        except:
            try:
                response = requests.head(f"https://{subdomain}", 
                                       headers=self.headers, 
                                       timeout=5, 
                                       allow_redirects=False)
                return f"{response.status_code}"
            except:
                return "Erişilemez"
    
    def save_results(self, output_file: str = None) -> str:
        """Sonuçları dosyaya kaydet"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"subdomains_{self.domain}_{timestamp}.txt"
        
        sorted_subdomains = sorted(list(self.subdomains))
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"{'='*70}\n")
                f.write(f"Subdomain Araştırması Sonuçları\n")
                f.write(f"{'='*70}\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Toplam Bulunan: {len(sorted_subdomains)} subdomain\n")
                f.write(f"{'='*70}\n\n")
                
                f.write("SUBDOMAIN LİSTESİ:\n")
                f.write("-" * 70 + "\n")
                
                verified_count = 0
                for idx, subdomain in enumerate(sorted_subdomains, 1):
                    is_active = self.verify_subdomain(subdomain)
                    status = "✓ Aktif" if is_active else "✗ Pasif"
                    if is_active:
                        verified_count += 1
                        http_status = self.check_http_response(subdomain)
                        f.write(f"{idx:3d}. {subdomain:<50} [{status}] HTTP: {http_status}\n")
                    else:
                        f.write(f"{idx:3d}. {subdomain:<50} [{status}]\n")
                
                f.write("\n" + "="*70 + "\n")
                f.write(f"Özet: {len(sorted_subdomains)} toplam, {verified_count} aktif\n")
                f.write("="*70 + "\n")
            
            return output_file
        except Exception as e:
            print(f"[-] Dosya kaydetme hatası: {e}")
            return None
    
    def run(self) -> None:
        """Araştırmayı çalıştır"""
        print(f"\n[*] '{self.domain}' için subdomain araması başlıyor...\n")
        
        self.search_crt_sh()
        print(f"[*] Şu ana kadar bulunan: {len(self.subdomains)} subdomain")
        
        print(f"\n[*] Sonuçlar kaydediliyor...\n")
        output_file = self.save_results()
        
        if output_file:
            print(f"[✓] Sonuçlar kaydedildi: {output_file}")
            print(f"[✓] Toplam {len(self.subdomains)} subdomain bulundu")
        else:
            print(f"[-] Sonuçlar kaydedilemedi!")


def print_banner():
    """Banner yazdır"""
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║  sAMeTTurk Sub_Scanner #v1.0                         ║
    ║  WebGuvenligi Team                                   ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Ana program"""
    print_banner()
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Domain adı girin (örn: example.com): ").strip()
    
    if not domain:
        print("[-] Domain adı boş olamaz!")
        return
    
    # Domain doğrulaması
    domain = domain.lower()
    if not domain.count('.'):
        print("[-] Geçerli bir domain girin!")
        return
    
    finder = SubdomainFinder(domain)
    finder.run()


if __name__ == "__main__":
    main()
