/**
 * WebGüvenliği - Subdomain Scanner
 * Frontend JavaScript Application
 */

class SubdomainScannerApp {
    constructor() {
        this.isScanning = false;
        this.currentResults = null;
        this.initializeElements();
        this.attachEventListeners();
    }

    initializeElements() {
        this.elements = {
            domainInput: document.getElementById('domainInput'),
            scanBtn: document.getElementById('scanBtn'),
            statusSection: document.getElementById('statusSection'),
            resultsSection: document.getElementById('resultsSection'),
            errorSection: document.getElementById('errorSection'),
            progressFill: document.getElementById('progressFill'),
            progressText: document.getElementById('progressText'),
            messagesContainer: document.getElementById('messagesContainer'),
            sourcesSummary: document.getElementById('sourcesSummary'),
            sourcesGrid: document.getElementById('sourcesGrid'),
            domainDisplay: document.getElementById('domainDisplay'),
            statusBadge: document.getElementById('statusBadge'),
            resultsTableBody: document.getElementById('resultsTableBody'),
            totalCount: document.getElementById('totalCount'),
            activeCount: document.getElementById('activeCount'),
            passiveCount: document.getElementById('passiveCount'),
            scanTime: document.getElementById('scanTime'),
            searchInput: document.getElementById('searchInput'),
            filterSelect: document.getElementById('filterSelect'),
            exportBtn: document.getElementById('exportBtn'),
            newScanBtn: document.getElementById('newScanBtn'),
            errorMessage: document.getElementById('errorMessage'),
            errorRetryBtn: document.getElementById('errorRetryBtn'),
            detailsModal: document.getElementById('detailsModal'),
            modalTitle: document.getElementById('modalTitle'),
            modalBody: document.getElementById('modalBody'),
            closeModal: document.querySelector('.close-modal')
        };
    }

    attachEventListeners() {
        this.elements.scanBtn.addEventListener('click', () => this.startScan());
        this.elements.domainInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.startScan();
        });
        this.elements.exportBtn.addEventListener('click', () => this.exportResults());
        this.elements.newScanBtn.addEventListener('click', () => this.resetUI());
        this.elements.errorRetryBtn.addEventListener('click', () => this.resetUI());
        this.elements.searchInput.addEventListener('input', () => this.filterResults());
        this.elements.filterSelect.addEventListener('change', () => this.filterResults());
        this.elements.closeModal.addEventListener('click', () => this.closeDetailsModal());
    }

    async startScan() {
        const domain = this.elements.domainInput.value.trim();

        if (!domain) {
            this.showError('Lütfen bir domain adı girin');
            return;
        }

        if (this.isScanning) {
            this.showError('Tarama zaten çalışıyor');
            return;
        }

        this.isScanning = true;
        this.resetUI();
        this.showStatusSection();
        this.elements.scanBtn.disabled = true;
        this.elements.scanBtn.innerHTML = '<span class="spinner">⏳</span> Tarama çalışıyor...';

        try {
            // Taramayı başlat
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Tarama başlatılamadı');
            }

            // Status'u poll et
            this.pollScanStatus();
        } catch (error) {
            this.showError(error.message);
            this.resetScanButton();
        }
    }

    async pollScanStatus() {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                if (data.running) {
                    // Güncellemeleri göster
                    this.updateStatus(data);
                } else {
                    // Tarama tamamlandı
                    clearInterval(pollInterval);
                    
                    if (data.results && !data.results.error) {
                        this.currentResults = data.results;
                        this.displayResults(data.results);
                    } else {
                        this.showError('Tarama sırasında bir hata oluştu');
                    }
                    
                    this.isScanning = false;
                    this.resetScanButton();
                }
            } catch (error) {
                clearInterval(pollInterval);
                this.showError('Status kontrol başarısız: ' + error.message);
                this.isScanning = false;
                this.resetScanButton();
            }
        }, 500); // Her 500ms'de kontrol et
    }

    updateStatus(data) {
        // Domain adını göster
        if (data.domain) {
            this.elements.domainDisplay.textContent = data.domain;
        }

        // İlerleme çubuğunu güncelle
        if (data.progress) {
            const progress = Math.min(data.progress * 10, 90);
            this.elements.progressFill.style.width = progress + '%';
            this.elements.progressText.textContent = data.message || 'İşleniyor...';
        }

        // Mesaj ekle
        if (data.message) {
            this.addMessage(data.message);
        }

        // Kaynakları göster
        if (data.sources && Object.keys(data.sources).length > 0) {
            this.displaySourcesSummary(data.sources);
        }
    }

    addMessage(message) {
        const timestamp = new Date().toLocaleTimeString('tr-TR');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message-item';
        messageDiv.textContent = `[${timestamp}] ${message}`;
        this.elements.messagesContainer.appendChild(messageDiv);
        this.elements.messagesContainer.scrollTop = this.elements.messagesContainer.scrollHeight;
    }

    displaySourcesSummary(sources) {
        this.elements.sourcesSummary.style.display = 'block';
        this.elements.sourcesGrid.innerHTML = '';

        Object.entries(sources).forEach(([source, count]) => {
            if (count > 0) {
                const sourceItem = document.createElement('div');
                sourceItem.className = 'source-item';
                sourceItem.innerHTML = `
                    <div class="source-name">${this.formatSourceName(source)}</div>
                    <div class="source-count">${count}</div>
                `;
                this.elements.sourcesGrid.appendChild(sourceItem);
            }
        });
    }

    formatSourceName(source) {
        const names = {
            'certspotter': '🎫 Certspotter',
            'ssl': '🔒 SSL Cert',
            'rapiddns': '⚡ RapidDNS',
            'sublist3r': '📡 Sublist3r',
            'omnisint': '🛰️ Omnisint'
        };
        return names[source] || source;
    }

    displayResults(results) {
        this.elements.statusSection.style.display = 'none';
        this.elements.resultsSection.style.display = 'block';
        this.elements.errorSection.style.display = 'none';

        // İstatistikleri güncelle
        this.elements.totalCount.textContent = results.total || 0;
        this.elements.activeCount.textContent = results.active || 0;
        this.elements.passiveCount.textContent = results.passive || 0;
        this.elements.scanTime.textContent = results.timestamp || '--:--';

        // Tabloyu doldur
        this.populateResultsTable(results.results || []);
    }

    populateResultsTable(results) {
        this.elements.resultsTableBody.innerHTML = '';

        if (results.length === 0) {
            this.elements.resultsTableBody.innerHTML = 
                '<tr><td colspan="5" class="loading">Sonuç bulunamadı</td></tr>';
            return;
        }

        results.forEach((result, index) => {
            const row = document.createElement('tr');
            const statusClass = result.active ? 'status-badge-active' : 'status-badge-passive';
            const statusText = result.active ? '✅ AKTİF' : '❌ PASİF';

            row.innerHTML = `
                <td>${index + 1}</td>
                <td>
                    <code style="background: #f7fafc; padding: 4px 8px; border-radius: 4px;">
                        ${this.escapeHtml(result.subdomain)}
                    </code>
                </td>
                <td><span class="${statusClass}">${statusText}</span></td>
                <td>
                    <span class="http-status">${this.escapeHtml(result.http)}</span>
                </td>
                <td>
                    <button class="action-btn" onclick="app.showDetails('${this.escapeHtml(result.subdomain)}', '${result.active}', '${this.escapeHtml(result.http)}')">
                        📋 Detay
                    </button>
                </td>
            `;

            this.elements.resultsTableBody.appendChild(row);
        });
    }

    filterResults() {
        const searchTerm = this.elements.searchInput.value.toLowerCase();
        const filterValue = this.elements.filterSelect.value;

        if (!this.currentResults || !this.currentResults.results) return;

        const filtered = this.currentResults.results.filter(result => {
            const matchesSearch = result.subdomain.toLowerCase().includes(searchTerm);
            const matchesFilter = 
                filterValue === 'all' ||
                (filterValue === 'active' && result.active) ||
                (filterValue === 'passive' && !result.active);

            return matchesSearch && matchesFilter;
        });

        this.populateResultsTable(filtered);
    }

    async exportResults() {
        if (!this.currentResults) {
            alert('Dışa aktarılacak sonuç yok');
            return;
        }

        try {
            const response = await fetch('/api/export');
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            // CSV dosyasını indir
            const element = document.createElement('a');
            element.setAttribute('href', 'data:text/csv;charset=utf-8,' + encodeURIComponent(data.content));
            element.setAttribute('download', data.filename);
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);

            this.addMessage(`✅ ${data.filename} indirildi`);
        } catch (error) {
            this.showError('Dışa aktarma başarısız: ' + error.message);
        }
    }

    showDetails(subdomain, active, http) {
        this.elements.modalTitle.textContent = subdomain;
        this.elements.modalBody.innerHTML = `
            <div style="text-align: left;">
                <p><strong>Subdomain:</strong> <code>${this.escapeHtml(subdomain)}</code></p>
                <p><strong>Durum:</strong> <span style="color: ${active === 'true' ? '#48bb78' : '#f56565'}">
                    ${active === 'true' ? '✅ Aktif' : '❌ Pasif'}
                </span></p>
                <p><strong>HTTP Status:</strong> <code>${this.escapeHtml(http)}</code></p>
                <p style="margin-top: 20px; color: #718096;">
                    <small>Bu subdomain ${new Date().toLocaleDateString('tr-TR')} tarihinde tarandı.</small>
                </p>
            </div>
        `;
        this.elements.detailsModal.style.display = 'flex';
    }

    closeDetailsModal() {
        this.elements.detailsModal.style.display = 'none';
    }

    showStatusSection() {
        this.elements.statusSection.style.display = 'block';
        this.elements.resultsSection.style.display = 'none';
        this.elements.errorSection.style.display = 'none';
        this.elements.messagesContainer.innerHTML = '';
        this.elements.sourcesSummary.style.display = 'none';
        this.elements.progressFill.style.width = '0%';
    }

    showError(message) {
        this.elements.statusSection.style.display = 'none';
        this.elements.resultsSection.style.display = 'none';
        this.elements.errorSection.style.display = 'block';
        this.elements.errorMessage.textContent = message;
    }

    resetUI() {
        this.elements.domainInput.value = '';
        this.elements.statusSection.style.display = 'none';
        this.elements.resultsSection.style.display = 'none';
        this.elements.errorSection.style.display = 'none';
        this.elements.searchInput.value = '';
        this.elements.filterSelect.value = 'all';
    }

    resetScanButton() {
        this.elements.scanBtn.disabled = false;
        this.elements.scanBtn.innerHTML = '<span class="btn-text">🚀 Taramayı Başlat</span>';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Uygulama başlat
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new SubdomainScannerApp();
    console.log('✅ WebGüvenliği - Subdomain Scanner Hazır');
});
