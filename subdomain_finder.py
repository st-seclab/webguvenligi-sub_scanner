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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class SubdomainFinder:
    """Subdomain bulma ve listeleme araci"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.found_sources = {
            'crt.sh': 0,
            'certspotter': 0,
            'ssl': 0,
            'rapiddns': 0
        }
        
    def create_session_with_retries(self, retries: int = 3) -> requests.Session:
        """Retry stratejisi ile session oluştur"""
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
        
    def search_crt_sh(self) -> None:
        """crt.sh üzerinden subdomain ara"""
        try:
            print("[*] crt.sh üzerinden aramalar yapiliyor...")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            session = self.create_session_with_retries()
            
            response = session.get(url, headers=self.headers, timeout=15, verify=False)
            
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
                                    self.found_sources['crt.sh'] += 1
                    print(f"[+] crt.sh: {self.found_sources['crt.sh']} yeni subdomain bulundu")
                except json.JSONDecodeError:
                    print(f"[-] crt.sh JSON hatasi")
            else:
                print(f"[-] crt.sh HTTP hatasi: {response.status_code}")
        except requests.exceptions.Timeout:
            print("[-] crt.sh: Zaman aşımı (timeout)")
        except requests.exceptions.ConnectionError:
            print("[-] crt.sh: Bağlantı hatası")
        except Exception as e:
            print(f"[-] crt.sh hatasi: {e}")
    
    def search_certspotter(self) -> None:
        """Cert Spotter üzerinden subdomain ara"""
        try:
            print("[*] Cert Spotter üzerinden aramalar yapiliyor...")
            url = f"https://certspotter.com/api/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            session = self.create_session_with_retries()
            
            response = session.get(url, headers=self.headers, timeout=15)
            
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
                                        if name not in self.subdomains:
                                            self.found_sources['certspotter'] += 1
                                        self.subdomains.add(name)
                    print(f"[+] Cert Spotter: {self.found_sources['certspotter']} yeni subdomain bulundu")
                except Exception:
                    pass
            else:
                print(f"[-] Cert Spotter HTTP hatasi: {response.status_code}")
        except requests.exceptions.Timeout:
            print("[-] Cert Spotter: Zaman aşımı (timeout)")
        except requests.exceptions.ConnectionError:
            print("[-] Cert Spotter: Bağlantı hatası")
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
                    
                    # Subject kontrol et - hata düzeltmesi
                    if cert and 'subject' in cert and cert['subject']:
                        try:
                            subject = dict(x[0] for x in cert['subject'])
                            if 'commonName' in subject:
                                cn = subject['commonName'].lower()
                                if cn.endswith(self.domain):
                                    if cn not in self.subdomains:
                                        self.found_sources['ssl'] += 1
                                    self.subdomains.add(cn)
                        except (ValueError, TypeError) as parse_error:
                            print(f"[!] SSL subject parse hatasi: {parse_error}")
                    
                    # subjectAltName kontrol et
                    for sub_alt in cert.get('subjectAltName', []):
                        if sub_alt[0] == 'DNS':
                            name = sub_alt[1].lower()
                            if self.domain in name or name.endswith(self.domain):
                                if name not in self.subdomains:
                                    self.found_sources['ssl'] += 1
                                self.subdomains.add(name)
                    
                    if self.found_sources['ssl'] > 0:
                        print(f"[+] SSL Sertifikasi: {self.found_sources['ssl']} yeni subdomain bulundu")
                    else:
                        print(f"[*] SSL Sertifikasi: Subdomain bulunamadi")
                        
        except socket.timeout:
            print("[-] SSL: Zaman aşımı (timeout)")
        except socket.gaierror:
            print("[-] SSL: Domain DNS'te bulunamadi")
        except ConnectionRefusedError:
            print("[-] SSL: 443 portu kapalı")
        except Exception as e:
            print(f"[-] SSL sertifikasi hatasi: {e}")
    
    def search_rapiddns(self) -> None:
        """RapidDNS üzerinden subdomain ara"""
        try:
            print("[*] RapidDNS üzerinden aramalar yapiliyor...")
            url = f"https://dns.bufferover.run/api/v1/query?q={self.domain}"
            session = self.create_session_with_retries(retries=3)
            
            try:
                response = session.get(url, headers=self.headers, timeout=15, verify=False)
            except requests.exceptions.Timeout:
                print("[-] RapidDNS: Zaman aşımı (timeout) - atlanıyor...")
                return
            except requests.exceptions.ConnectionError:
                print("[-] RapidDNS: Bağlantı hatası - atlanıyor...")
                return
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'FDNS_A' in data:
                        for entry in data['FDNS_A']:
                            parts = entry.split(',')
                            if len(parts) >= 1:
                                subdomain = parts[0].lower()
                                if subdomain and (self.domain in subdomain or subdomain.endswith(self.domain)):
                                    if subdomain not in self.subdomains:
                                        self.found_sources['rapiddns'] += 1
                                    self.subdomains.add(subdomain)
                        print(f"[+] RapidDNS: {self.found_sources['rapiddns']} yeni subdomain bulundu")
                    else:
                        print(f"[*] RapidDNS: Veri bulunamadi")
                except json.JSONDecodeError:
                    print(f"[-] RapidDNS JSON hatasi")
            else:
                print(f"[-] RapidDNS HTTP hatasi: {response.status_code}")
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
                                   allow_redirects=False,
                                   verify=False)
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
                
                # Kaynaklar özeti
                f.write("KAYNAK ÖZETİ:\n")
                f.write("-" * 80 + "\n")
                for source, count in self.found_sources.items():
                    f.write(f"{source:<20}: {count:>3} subdomain\n")
                f.write("-" * 80 + "\n\n")
                
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
    
    def run(self, debug: bool = False) -> None:
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
            print(f"[!] UYARÍ: Subdomain bulunamadi!")
            print(f"\n[?] Olası Nedenler:")
            print(f"    • Domain geçerli olmayabilir")
            print(f"    • Ağ bağlantı sorunu olabilir")
            print(f"    • API'ler yanıt vermeyebilir")
            print(f"    • Domain'e ait subdomain'ler olmayabilir")
            
            if debug:
                print(f"\n[DEBUG] Bulunan kaynaklar:")
                total_found = sum(self.found_sources.values())
                for source, count in self.found_sources.items():
                    print(f"    {source}: {count}")
                print(f"    TOPLAM: {total_found}")


def print_banner():
    """Banner yazdir"""
    banner = """
    =================================================================
    sAMeTTurk Sub_Scanner #v1.1 [FIXED]
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
    
    # Debug modu için -d parametresi
    debug_mode = '-d' in sys.argv or '--debug' in sys.argv
    
    finder = SubdomainFinder(domain)
    finder.run(debug=debug_mode)


if __name__ == "__main__":
    main()
