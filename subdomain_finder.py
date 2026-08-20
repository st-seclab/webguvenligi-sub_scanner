#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Listeleyici Araç
Belirtilen domain için subdomain araması yapar ve sonuçları dosyaya kaydeder.
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
    """Subdomain bulma ve listeleme aracı"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.base_domain = self._extract_base_domain(domain)  # example.com
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        # Toplam 5 servis: certspotter, ssl (sertifika), rapiddns (bufferover), sublist3r, omnisint
        self.found_sources = {
            'certspotter': 0,
            'ssl': 0,
            'rapiddns': 0,
            'sublist3r': 0,
            'omnisint': 0
        }
    
    def _extract_base_domain(self, domain: str) -> str:
        """Ana domain'i çıkar (example.com, domain.co.uk vs)"""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain.lower()
        
    def normalize_subdomain(self, name: str) -> str:
        """Subdomain adını normalize et: küçük harfe çevir, boşlukları temizle, '*.' ve sona gelen noktayı çıkar"""
        if not name:
            return ''
        name = name.strip().lower()
        # Bazı kaynaklar satır içinde ana domainleri "*.example.com" gibi verebilir
        if name.startswith('*.'):
            name = name[2:]
        # Remove trailing dot
        if name.endswith('.'):
            name = name[:-1]
        return name
    
    def is_valid_subdomain(self, subdomain: str) -> bool:
        """Subdomainin geçerli olup olmadığını kontrol et"""
        if not subdomain or len(subdomain) < 3:
            return False
        
        # Subdomain'in ana domain'le ilişkili olup olmadığını kontrol et
        if subdomain == self.base_domain:
            # Ana domain kendisi değil, sadece subdomainler istiyoruz
            return False
        
        if subdomain.endswith(self.base_domain):
            return True
        
        # Eğer domain sadece FQDN değilse, daha esnek bir kontrol yap
        if self.base_domain in subdomain:
            return True
            
        return False

    def create_session_with_retries(self, retries: int = 2) -> requests.Session:
        """Retry stratejisi ile session oluştur"""
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=0.5
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
        
    def search_certspotter(self) -> None:
        """Cert Spotter üzerinden subdomain ara"""
        try:
            print("[*] Cert Spotter üzerinden aramalar yapılıyor...")
            url = f"https://certspotter.com/api/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            session = self.create_session_with_retries(retries=2)
            
            response = session.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        for entry in data:
                            dns_names = entry.get('dns_names', [])
                            if isinstance(dns_names, list):
                                for name in dns_names:
                                    norm = self.normalize_subdomain(name)
                                    if norm and self.is_valid_subdomain(norm):
                                        if norm not in self.subdomains:
                                            self.found_sources['certspotter'] += 1
                                            self.subdomains.add(norm)
                        print(f"[+] Cert Spotter: {self.found_sources['certspotter']} yeni subdomain bulundu")
                    else:
                        print("[*] Cert Spotter: Sonuç bulunamadı")
                except Exception as e:
                    print(f"[-] Cert Spotter parse hatası: {str(e)[:200]}")
            elif response.status_code == 410:
                print("[*] Cert Spotter: Geçici olarak kullanılamıyor (HTTP 410)")
            else:
                print(f"[-] Cert Spotter HTTP hatası: {response.status_code}")
        except requests.exceptions.Timeout:
            print("[-] Cert Spotter: Zaman aşımı (timeout)")
        except requests.exceptions.ConnectionError:
            print("[-] Cert Spotter: Bağlantı hatası")
        except Exception as e:
            print(f"[-] Cert Spotter hatası: {str(e)[:200]}")
    
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
                    
                    if cert and 'subject' in cert and cert['subject']:
                        try:
                            subject = dict(x[0] for x in cert['subject'])
                            if 'commonName' in subject:
                                cn = self.normalize_subdomain(subject['commonName'])
                                if cn and self.is_valid_subdomain(cn):
                                    if cn not in self.subdomains:
                                        self.found_sources['ssl'] += 1
                                        self.subdomains.add(cn)
                        except (ValueError, TypeError):
                            pass
                    
                    for sub_alt in cert.get('subjectAltName', []):
                        if sub_alt[0] == 'DNS':
                            name = self.normalize_subdomain(sub_alt[1])
                            if name and self.is_valid_subdomain(name):
                                if name not in self.subdomains:
                                    self.found_sources['ssl'] += 1
                                    self.subdomains.add(name)
                    
                    if self.found_sources['ssl'] > 0:
                        print(f"[+] SSL Sertifikası: {self.found_sources['ssl']} yeni subdomain bulundu")
                    else:
                        print("[*] SSL Sertifikası: Subdomain bulunamadı")
                        
        except socket.timeout:
            print("[-] SSL: Zaman aşımı (timeout)")
        except socket.gaierror:
            print("[-] SSL: Domain DNS'te bulunamadı")
        except ConnectionRefusedError:
            print("[-] SSL: 443 portu kapalı")
        except Exception as e:
            print(f"[-] SSL hatası: {str(e)[:200]}")
    
    def search_rapiddns(self) -> None:
        """RapidDNS üzerinden subdomain ara"""
        try:
            print("[*] RapidDNS üzerinden aramalar yapılıyor...")
            url = f"https://dns.bufferover.run/api/v1/query?q={self.domain}"
            session = self.create_session_with_retries(retries=2)
            
            try:
                response = session.get(url, headers=self.headers, timeout=10, verify=False)
            except requests.exceptions.Timeout:
                print("[-] RapidDNS: Zaman aşımı (timeout) - atlanıyor...")
                return
            except requests.exceptions.ConnectionError:
                print("[-] RapidDNS: Bağlantı hatası - atlanıyor...")
                return
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'FDNS_A' in data and len(data['FDNS_A']) > 0:
                        for entry in data['FDNS_A']:
                            parts = entry.split(',')
                            if len(parts) >= 1:
                                subdomain = self.normalize_subdomain(parts[0])
                                if subdomain and self.is_valid_subdomain(subdomain):
                                    if subdomain not in self.subdomains:
                                        self.found_sources['rapiddns'] += 1
                                        self.subdomains.add(subdomain)
                        print(f"[+] RapidDNS: {self.found_sources['rapiddns']} yeni subdomain bulundu")
                    else:
                        print("[*] RapidDNS: Sonuç bulunamadı")
                except json.JSONDecodeError:
                    print("[-] RapidDNS JSON hatası")
            else:
                print(f"[-] RapidDNS HTTP hatası: {response.status_code}")
        except Exception as e:
            print(f"[-] RapidDNS hatası: {str(e)[:200]}")
    
    def search_sublist3r(self) -> None:
        """Sublist3r public API üzerinden subdomain ara (basit ve hızlı)"""
        try:
            print("[*] Sublist3r API üzerinden aramalar yapılıyor...")
            url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
            session = self.create_session_with_retries(retries=2)
            try:
                response = session.get(url, headers=self.headers, timeout=10)
            except requests.exceptions.Timeout:
                print("[-] Sublist3r: Zaman aşımı (timeout)")
                return
            except requests.exceptions.ConnectionError:
                print("[-] Sublist3r: Bağlantı hatası")
                return
            
            if response.status_code == 200:
                try:
                    # Bazı durumlarda JSON, bazen düz metin satırlar halinde gelmektedir
                    try:
                        data = response.json()
                    except Exception:
                        data = response.text.strip().split('\n') if response.text else []

                    if isinstance(data, list) and len(data) > 0:
                        for name in data:
                            norm = self.normalize_subdomain(name)
                            if norm and self.is_valid_subdomain(norm):
                                if norm not in self.subdomains:
                                    self.found_sources['sublist3r'] += 1
                                    self.subdomains.add(norm)
                        print(f"[+] Sublist3r: {self.found_sources['sublist3r']} yeni subdomain bulundu")
                    else:
                        print("[*] Sublist3r: Sonuç bulunamadı")
                except Exception as e:
                    print(f"[-] Sublist3r parse hatası: {str(e)[:200]}")
            else:
                print(f"[-] Sublist3r HTTP hatası: {response.status_code}")
        except Exception as e:
            print(f"[-] Sublist3r hatası: {str(e)[:200]}")
    
    def search_omnisint(self) -> None:
        """Omnisint / sonar API üzerinden subdomain ara (https://sonar.omnisint.io)"""
        try:
            print("[*] Omnisint (sonar) üzerinden aramalar yapılıyor...")
            url = f"https://sonar.omnisint.io/subdomains/{self.domain}"
            session = self.create_session_with_retries(retries=2)
            try:
                response = session.get(url, headers=self.headers, timeout=10)
            except requests.exceptions.Timeout:
                print("[-] Omnisint: Zaman aşımı (timeout)")
                return
            except requests.exceptions.ConnectionError:
                print("[-] Omnisint: Bağlantı hatası")
                return
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        for name in data:
                            norm = self.normalize_subdomain(name)
                            if norm and self.is_valid_subdomain(norm):
                                if norm not in self.subdomains:
                                    self.found_sources['omnisint'] += 1
                                    self.subdomains.add(norm)
                        print(f"[+] Omnisint: {self.found_sources['omnisint']} yeni subdomain bulundu")
                    else:
                        print("[*] Omnisint: Sonuç bulunamadı")
                except Exception as e:
                    print(f"[-] Omnisint parse hatası: {str(e)[:200]}")
            elif response.status_code == 404:
                print("[*] Omnisint: Veri bulunamadı (404)")
            else:
                print(f"[-] Omnisint HTTP hatası: {response.status_code}")
        except Exception as e:
            print(f"[-] Omnisint hatası: {str(e)[:200]}")
    
    def verify_subdomain(self, subdomain: str) -> bool:
        """Subdomain DNS kaydını doğrula"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except (socket.gaierror, socket.error):
            return False
    
    def check_http_response(self, subdomain: str) -> str:
        """HTTP yanıtını kontrol et"""
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
        """Dosyayı işletim sistemine göre aç"""
        try:
            if platform.system() == 'Windows':
                os.startfile(file_path)
            elif platform.system() == 'Darwin':
                subprocess.Popen(['open', file_path])
            else:
                subprocess.Popen(['xdg-open', file_path])
            print(f"[OK] Dosya açıldı: {file_path}")
        except Exception as e:
            print(f"[-] Dosya açılamadı: {e}")
    
    def save_results(self, output_file: str = None) -> str:
        """Sonuçları dosyaya kaydet"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"subdomains_{self.domain}_{timestamp}.txt"
        
        sorted_subdomains = sorted(list(self.subdomains))
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("Subdomain Araştırması Sonuçları\n")
                f.write("="*80 + "\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Toplam Bulunan: {len(sorted_subdomains)} subdomain\n")
                f.write("="*80 + "\n\n")
                
                # Kaynaklar özeti
                f.write("KAYNAK ÖZETİ:\n")
                f.write("-" * 80 + "\n")
                total_from_sources = 0
                for source, count in self.found_sources.items():
                    if count > 0:
                        f.write(f"{source:<20}: {count:>3} subdomain\n")
                        total_from_sources += count
                f.write(f"{'TOPLAM':<20}: {total_from_sources:>3} subdomain\n")
                f.write("-" * 80 + "\n\n")
                
                f.write("SUBDOMAIN LİSTESİ:\n")
                f.write("-" * 80 + "\n")
                f.write(f"{('#'):<5} {'SUBDOMAIN':<50} {'DURUM':<15} {'HTTP':<10}\n")
                f.write("-" * 80 + "\n")
                
                verified_count = 0
                for idx, subdomain in enumerate(sorted_subdomains, 1):
                    is_active = self.verify_subdomain(subdomain)
                    status = "[AKTİF]" if is_active else "[PASİF]"
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
            print(f"[-] Dosya kaydetme hatası: {e}")
            return None
    
    def run(self, debug: bool = False) -> None:
        """Araştırmayı çalıştır"""
        print(f"\n[*] '{self.domain}' için subdomain araması başlıyor...\n")
        
        # Yeni sıralama: certspotter, ssl, rapiddns, sublist3r, omnisint
        self.search_certspotter()
        self.search_ssl_certificates()
        self.search_rapiddns()
        self.search_sublist3r()
        self.search_omnisint()
        
        print(f"\n[*] Şu ana kadar bulunan: {len(self.subdomains)} benzersiz subdomain\n")
        
        if len(self.subdomains) > 0:
            print("[*] Sonuçlar kaydediliyor...\n")
            output_file = self.save_results()
            
            if output_file:
                print(f"[OK] Sonuçlar kaydedildi: {output_file}")
                print(f"[OK] Toplam {len(self.subdomains)} subdomain bulundu")
                print("\n[*] Dosya açılıyor...\n")
                self.open_file(output_file)
            else:
                print("[HATA] Sonuçlar kaydedilemedi!")
        else:
            print("[!] UYARI: Subdomain bulunamadı!")
            print("\n[?] Olası Nedenler:")
            print("    • Domain geçerli olmayabilir (domain.com formatında girin)")
            print("    • Ağ bağlantı sorunu (VPN/Proxy yapılandırması kontrol edin)")
            print("    • API'ler geçici olarak sorun yaşayabilir")
            print("    • Domain'e ait halka açık subdomain'ler olmayabilir")
            print("\n[*] Lütfen birkaç saniye sonra tekrar deneyin!")
            
            if debug:
                print("\n[DEBUG] Bulunan kaynaklar:")
                total_found = sum(self.found_sources.values())
                for source, count in self.found_sources.items():
                    print(f"    {source}: {count}")
                print(f"    TOPLAM: {total_found}")


def print_banner():
    """Banner yazdır"""
    banner = """
    =================================================================
    sAMeTTurk Sub_Scanner #v1.3 [FIXED]
    WebGüvenliği Team
    
    Çoklu Kaynak Subdomain Keşif Aracı
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
        domain = input("\n[?] Domain adı girin (örn: example.com): ").strip()
    
    if not domain:
        print("[-] Domain adı boş olamaz!")
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
