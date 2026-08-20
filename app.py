#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Güvenliği - Subdomain Scanner Web Uygulaması
Flask backend - subdomain_finder.py ile entegre
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import socket
import ssl
import requests
import threading
from datetime import datetime
from typing import Set, Dict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# Global scan status tracker
scan_status = {
    'running': False,
    'domain': '',
    'progress': 0,
    'results': [],
    'sources': {},
    'message': ''
}


class SubdomainFinder:
    """Subdomain bulma ve listeleme aracı"""
    
    def __init__(self, domain: str, callback=None):
        self.domain = domain
        self.base_domain = self._extract_base_domain(domain)  # example.com
        self.subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.found_sources = {
            'certspotter': 0,
            'ssl': 0,
            'rapiddns': 0,
            'sublist3r': 0,
            'omnisint': 0
        }
        self.callback = callback
    
    def _extract_base_domain(self, domain: str) -> str:
        """Ana domain'i çıkar (example.com, domain.co.uk vs)"""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain.lower()
        
    def update_progress(self, message: str, step: int = 1):
        """İlerleme callback'i"""
        if self.callback:
            self.callback(message, step)
    
    def normalize_subdomain(self, name: str) -> str:
        """Subdomain adını normalize et"""
        if not name:
            return ''
        name = name.strip().lower()
        if name.startswith('*.'):
            name = name[2:]
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
            self.update_progress("🔍 Cert Spotter taranıyor...", 1)
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
                        self.update_progress(f"✅ Cert Spotter: {self.found_sources['certspotter']} subdomain bulundu", 1)
                    else:
                        self.update_progress("⚪ Cert Spotter: Sonuç bulunamadı", 1)
                except Exception as e:
                    self.update_progress(f"⚠️ Cert Spotter parse hatası: {str(e)[:100]}", 1)
            else:
                self.update_progress(f"⚠️ Cert Spotter HTTP {response.status_code}", 1)
        except requests.exceptions.Timeout:
            self.update_progress("⏱️ Cert Spotter: Timeout", 1)
        except Exception as e:
            self.update_progress(f"❌ Cert Spotter hatası", 1)
    
    def search_ssl_certificates(self) -> None:
        """SSL sertifikalarından subdomain ara"""
        try:
            self.update_progress("🔒 SSL sertifikaları taranıyor...", 1)
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
                        self.update_progress(f"✅ SSL: {self.found_sources['ssl']} subdomain bulundu", 1)
                    else:
                        self.update_progress("⚪ SSL: Subdomain bulunamadı", 1)
                        
        except socket.timeout:
            self.update_progress("⏱️ SSL: Timeout", 1)
        except socket.gaierror:
            self.update_progress("⚠️ SSL: Domain bulunamadı", 1)
        except ConnectionRefusedError:
            self.update_progress("⚠️ SSL: Port 443 kapalı", 1)
        except Exception as e:
            self.update_progress("❌ SSL hatası", 1)
    
    def search_rapiddns(self) -> None:
        """RapidDNS üzerinden subdomain ara"""
        try:
            self.update_progress("🌐 RapidDNS taranıyor...", 1)
            url = f"https://dns.bufferover.run/api/v1/query?q={self.domain}"
            session = self.create_session_with_retries(retries=2)
            
            try:
                response = session.get(url, headers=self.headers, timeout=10, verify=False)
            except requests.exceptions.Timeout:
                self.update_progress("⏱️ RapidDNS: Timeout", 1)
                return
            except requests.exceptions.ConnectionError:
                self.update_progress("⚠️ RapidDNS: Bağlantı hatası", 1)
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
                        self.update_progress(f"✅ RapidDNS: {self.found_sources['rapiddns']} subdomain bulundu", 1)
                    else:
                        self.update_progress("⚪ RapidDNS: Sonuç bulunamadı", 1)
                except json.JSONDecodeError:
                    self.update_progress("⚠️ RapidDNS: JSON hatası", 1)
            else:
                self.update_progress(f"⚠️ RapidDNS HTTP {response.status_code}", 1)
        except Exception as e:
            self.update_progress("❌ RapidDNS hatası", 1)
    
    def search_sublist3r(self) -> None:
        """Sublist3r API üzerinden subdomain ara"""
        try:
            self.update_progress("📡 Sublist3r API taranıyor...", 1)
            url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
            session = self.create_session_with_retries(retries=2)
            try:
                response = session.get(url, headers=self.headers, timeout=10)
            except requests.exceptions.Timeout:
                self.update_progress("⏱️ Sublist3r: Timeout", 1)
                return
            except requests.exceptions.ConnectionError:
                self.update_progress("⚠️ Sublist3r: Bağlantı hatası", 1)
                return
            
            if response.status_code == 200:
                try:
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
                        self.update_progress(f"✅ Sublist3r: {self.found_sources['sublist3r']} subdomain bulundu", 1)
                    else:
                        self.update_progress("⚪ Sublist3r: Sonuç bulunamadı", 1)
                except Exception as e:
                    self.update_progress(f"⚠️ Sublist3r parse hatası", 1)
            else:
                self.update_progress(f"⚠️ Sublist3r HTTP {response.status_code}", 1)
        except Exception as e:
            self.update_progress("❌ Sublist3r hatası", 1)
    
    def search_omnisint(self) -> None:
        """Omnisint/sonar API üzerinden subdomain ara"""
        try:
            self.update_progress("🛰️ Omnisint (sonar) taranıyor...", 1)
            url = f"https://sonar.omnisint.io/subdomains/{self.domain}"
            session = self.create_session_with_retries(retries=2)
            try:
                response = session.get(url, headers=self.headers, timeout=10)
            except requests.exceptions.Timeout:
                self.update_progress("⏱️ Omnisint: Timeout", 1)
                return
            except requests.exceptions.ConnectionError:
                self.update_progress("⚠️ Omnisint: Bağlantı hatası", 1)
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
                        self.update_progress(f"✅ Omnisint: {self.found_sources['omnisint']} subdomain bulundu", 1)
                    else:
                        self.update_progress("⚪ Omnisint: Sonuç bulunamadı", 1)
                except Exception as e:
                    self.update_progress(f"⚠️ Omnisint parse hatası", 1)
            elif response.status_code == 404:
                self.update_progress("⚠️ Omnisint: Veri bulunamadı (404)", 1)
            else:
                self.update_progress(f"⚠️ Omnisint HTTP {response.status_code}", 1)
        except Exception as e:
            self.update_progress("❌ Omnisint hatası", 1)
    
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
    
    def run(self) -> Dict:
        """Araştırmayı çalıştır ve sonuçları döndür"""
        self.update_progress(f"🚀 '{self.domain}' için tarama başlıyor...", 0)
        
        self.search_certspotter()
        self.search_ssl_certificates()
        self.search_rapiddns()
        self.search_sublist3r()
        self.search_omnisint()
        
        self.update_progress(f"📊 Toplam {len(self.subdomains)} benzersiz subdomain bulundu", 1)
        
        # Sonuçları işle
        sorted_subdomains = sorted(list(self.subdomains))
        results = []
        verified_count = 0
        
        self.update_progress("✔️ Subdomainler doğrulanıyor...", 1)
        
        for subdomain in sorted_subdomains:
            is_active = self.verify_subdomain(subdomain)
            if is_active:
                verified_count += 1
                http_status = self.check_http_response(subdomain)
            else:
                http_status = "-"
            
            results.append({
                'subdomain': subdomain,
                'active': is_active,
                'status': 'AKTİF' if is_active else 'PASİF',
                'http': http_status
            })
        
        self.update_progress("✨ Tarama tamamlandı!", 1)
        
        return {
            'domain': self.domain,
            'total': len(sorted_subdomains),
            'active': verified_count,
            'passive': len(sorted_subdomains) - verified_count,
            'results': results,
            'sources': self.found_sources,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }


@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Subdomain taraması başlat"""
    global scan_status
    
    data = request.json
    domain = data.get('domain', '').strip().lower()
    
    if not domain:
        return jsonify({'error': 'Domain adı gerekli'}), 400
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    if not domain.count('.') or len(domain) < 3:
        return jsonify({'error': 'Geçerli bir domain girin'}), 400
    
    if scan_status['running']:
        return jsonify({'error': 'Tarama zaten çalışıyor'}), 400
    
    # Taramayı background'da başlat
    scan_status['running'] = True
    scan_status['domain'] = domain
    scan_status['progress'] = 0
    scan_status['results'] = []
    scan_status['sources'] = {}
    scan_status['message'] = 'Başlatılıyor...'
    
    def callback(message: str, step: int):
        """İlerleme callback'i"""
        scan_status['message'] = message
        scan_status['progress'] += step
    
    def run_scan():
        """Taramayı çalıştır"""
        try:
            finder = SubdomainFinder(domain, callback=callback)
            result = finder.run()
            scan_status['results'] = result
            scan_status['sources'] = result['sources']
        except Exception as e:
            scan_status['results'] = {'error': str(e)}
        finally:
            scan_status['running'] = False
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({'status': 'started', 'domain': domain}), 200


@app.route('/api/status', methods=['GET'])
def get_status():
    """Tarama durumunu al"""
    return jsonify({
        'running': scan_status['running'],
        'domain': scan_status['domain'],
        'progress': scan_status['progress'],
        'message': scan_status['message'],
        'results': scan_status['results'],
        'sources': scan_status['sources']
    }), 200


@app.route('/api/export', methods=['GET'])
def export_results():
    """Sonuçları dışa aktar"""
    results = scan_status['results']
    
    if not results or 'error' in results:
        return jsonify({'error': 'Sonuç bulunamadı'}), 404
    
    # CSV formatında dışa aktar
    csv_content = "SUBDOMAIN,DURUM,HTTP STATUS\n"
    for item in results.get('results', []):
        csv_content += f"{item['subdomain']},{item['status']},{item['http']}\n"
    
    return jsonify({
        'filename': f"subdomains_{results['domain']}.csv",
        'content': csv_content
    }), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
