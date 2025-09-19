// NetNAT Web Application
class NetNATApp {
    constructor() {
        this.csrfToken = null;
        this.currentRule = null;
        this.refreshInterval = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.getCSRFToken();
        this.loadSystemStatus();
        this.loadRules();
        this.loadVMs();
        this.loadBackups();
        
        // Auto-refresh every 30 seconds
        this.refreshInterval = setInterval(() => {
            this.loadSystemStatus();
        }, 30000);
    }

    setupEventListeners() {
        // Quick Actions
        document.getElementById('enable-nat').addEventListener('click', () => this.enableNAT());
        document.getElementById('disable-nat').addEventListener('click', () => this.disableNAT());
        document.getElementById('refresh-vms').addEventListener('click', () => this.refreshVMs());
        document.getElementById('backup-now').addEventListener('click', () => this.createBackup());

        // Rules
        document.getElementById('add-rule-btn').addEventListener('click', () => this.showRuleModal());
        document.getElementById('saveRule').addEventListener('click', () => this.saveRule());

        // VMs
        document.getElementById('refresh-vms-btn').addEventListener('click', () => this.refreshVMs());

        // Backup
        document.getElementById('create-backup-btn').addEventListener('click', () => this.createBackup());

        // Quick Forward
        document.getElementById('createQuickForward').addEventListener('click', () => this.createQuickForward());

        // Tab switching
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                const target = e.target.getAttribute('href').substring(1);
                this.onTabSwitch(target);
            });
        });
    }

    onTabSwitch(tabName) {
        switch (tabName) {
            case 'rules':
                this.loadRules();
                break;
            case 'vms':
                this.loadVMs();
                break;
            case 'backup':
                this.loadBackups();
                break;
        }
    }

    // CSRF Token Management
    async getCSRFToken() {
        try {
            const response = await this.makeRequest('/api/csrf-token');
            if (response.success) {
                this.csrfToken = response.data.token;
            }
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
        }
    }

    // HTTP Request Helper
    async makeRequest(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (options.method && options.method !== 'GET' && this.csrfToken) {
            defaultOptions.headers['X-CSRF-Token'] = this.csrfToken;
        }

        const config = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers,
            },
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        } catch (error) {
            this.showAlert(error.message, 'danger');
            throw error;
        }
    }

    // System Status
    async loadSystemStatus() {
        try {
            const response = await this.makeRequest('/api/status');
            if (response.success) {
                this.updateSystemStatus(response.data);
            }
        } catch (error) {
            console.error('Failed to load system status:', error);
        }
    }

    updateSystemStatus(status) {
        // Update status badges
        document.getElementById('nat-status').className = 
            `badge ${status.nat_enabled ? 'bg-success' : 'bg-danger'}`;
        document.getElementById('nat-status').textContent = 
            status.nat_enabled ? 'Enabled' : 'Disabled';

        document.getElementById('forward-status').className = 
            `badge ${status.ip_forward_enabled ? 'bg-success' : 'bg-danger'}`;
        document.getElementById('forward-status').textContent = 
            status.ip_forward_enabled ? 'Enabled' : 'Disabled';

        document.getElementById('active-rules').textContent = status.active_rules || 0;
        document.getElementById('total-rules').textContent = status.rules_count || 0;

        document.getElementById('public-interface').textContent = status.public_interface || '-';
        document.getElementById('internal-bridge').textContent = status.internal_bridge || '-';

        // Update navbar status
        const systemStatus = document.getElementById('system-status');
        if (status.nat_enabled && status.ip_forward_enabled) {
            systemStatus.className = 'badge bg-success';
            systemStatus.innerHTML = '<i class="bi bi-circle-fill"></i> Online';
        } else {
            systemStatus.className = 'badge bg-warning';
            systemStatus.innerHTML = '<i class="bi bi-circle-fill"></i> Partial';
        }
    }

    // NAT Control
    async enableNAT() {
        try {
            const response = await this.makeRequest('/api/nat/enable', { method: 'POST' });
            if (response.success) {
                this.showAlert(response.message, 'success');
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to enable NAT:', error);
        }
    }

    async disableNAT() {
        if (!confirm('Are you sure you want to disable NAT? This will stop all port forwarding.')) {
            return;
        }
        
        try {
            const response = await this.makeRequest('/api/nat/disable', { method: 'POST' });
            if (response.success) {
                this.showAlert(response.message, 'warning');
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to disable NAT:', error);
        }
    }

    // Rules Management
    async loadRules() {
        try {
            const response = await this.makeRequest('/api/rules');
            if (response.success) {
                this.updateRulesTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load rules:', error);
        }
    }

    updateRulesTable(rules) {
        const tbody = document.querySelector('#rules-table tbody');
        tbody.innerHTML = '';

        rules.forEach(rule => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${rule.name}</td>
                <td>${rule.external_port}</td>
                <td>${rule.internal_ip}</td>
                <td>${rule.internal_port}</td>
                <td>${rule.protocol.toUpperCase()}</td>
                <td>
                    <span class="badge ${rule.enabled ? 'bg-success' : 'bg-secondary'}">
                        ${rule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                </td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="app.editRule('${rule.id}')">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-outline-secondary" onclick="app.toggleRule('${rule.id}')">
                            <i class="bi bi-${rule.enabled ? 'pause' : 'play'}"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="app.deleteRule('${rule.id}')">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    showRuleModal(rule = null) {
        this.currentRule = rule;
        const modal = new bootstrap.Modal(document.getElementById('ruleModal'));
        const title = document.getElementById('ruleModalTitle');
        
        if (rule) {
            title.textContent = 'Edit Port Forwarding Rule';
            document.getElementById('ruleName').value = rule.name;
            document.getElementById('externalPort').value = rule.external_port;
            document.getElementById('internalIP').value = rule.internal_ip;
            document.getElementById('internalPort').value = rule.internal_port;
            document.getElementById('protocol').value = rule.protocol;
            document.getElementById('ruleEnabled').checked = rule.enabled;
        } else {
            title.textContent = 'Add Port Forwarding Rule';
            document.getElementById('ruleForm').reset();
            document.getElementById('ruleEnabled').checked = true;
        }
        
        modal.show();
    }

    async editRule(id) {
        try {
            const response = await this.makeRequest(`/api/rules/${id}`);
            if (response.success) {
                this.showRuleModal(response.data);
            }
        } catch (error) {
            console.error('Failed to load rule:', error);
        }
    }

    async saveRule() {
        const form = document.getElementById('ruleForm');
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        const rule = {
            name: document.getElementById('ruleName').value,
            external_port: parseInt(document.getElementById('externalPort').value),
            internal_ip: document.getElementById('internalIP').value,
            internal_port: parseInt(document.getElementById('internalPort').value),
            protocol: document.getElementById('protocol').value,
            enabled: document.getElementById('ruleEnabled').checked,
        };

        try {
            const url = this.currentRule ? `/api/rules/${this.currentRule.id}` : '/api/rules';
            const method = this.currentRule ? 'PUT' : 'POST';
            
            const response = await this.makeRequest(url, {
                method: method,
                body: JSON.stringify(rule),
            });

            if (response.success) {
                this.showAlert(response.message, 'success');
                bootstrap.Modal.getInstance(document.getElementById('ruleModal')).hide();
                this.loadRules();
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to save rule:', error);
        }
    }

    async toggleRule(id) {
        try {
            const response = await this.makeRequest(`/api/rules/${id}/toggle`, { method: 'POST' });
            if (response.success) {
                this.showAlert(response.message, 'info');
                this.loadRules();
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to toggle rule:', error);
        }
    }

    async deleteRule(id) {
        if (!confirm('Are you sure you want to delete this rule?')) {
            return;
        }

        try {
            const response = await this.makeRequest(`/api/rules/${id}`, { method: 'DELETE' });
            if (response.success) {
                this.showAlert(response.message, 'warning');
                this.loadRules();
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to delete rule:', error);
        }
    }

    // VMs Management
    async loadVMs() {
        try {
            const response = await this.makeRequest('/api/vms');
            if (response.success) {
                this.updateVMsTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load VMs:', error);
        }
    }

    updateVMsTable(vms) {
        const tbody = document.querySelector('#vms-table tbody');
        tbody.innerHTML = '';

        vms.forEach(vm => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${vm.id}</td>
                <td>${vm.name || '-'}</td>
                <td>
                    <span class="badge ${vm.type === 'qemu' ? 'bg-primary' : vm.type === 'lxc' ? 'bg-info' : 'bg-secondary'}">
                        ${vm.type.toUpperCase()}
                    </span>
                </td>
                <td><code>${vm.ip || '-'}</code></td>
                <td>
                    <span class="badge ${vm.status === 'running' ? 'bg-success' : 'bg-secondary'}">
                        ${vm.status}
                    </span>
                </td>
                <td><small>${vm.source}</small></td>
                <td>
                    ${vm.ip ? `
                        <button class="btn btn-sm btn-outline-primary" onclick="app.quickForward('${vm.id}', '${vm.ip}', '${vm.name}')">
                            <i class="bi bi-arrow-right-circle"></i> Forward Port
                        </button>
                    ` : '-'}
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async refreshVMs() {
        try {
            const response = await this.makeRequest('/api/vms/refresh', { method: 'POST' });
            if (response.success) {
                this.showAlert('VM list refreshed', 'info');
                this.loadVMs();
            }
        } catch (error) {
            console.error('Failed to refresh VMs:', error);
        }
    }

    quickForward(vmId, ip, name) {
        const modal = new bootstrap.Modal(document.getElementById('quickForwardModal'));
        document.getElementById('targetInfo').value = `${name} (${vmId}) - ${ip}`;
        document.getElementById('targetIP').value = ip;
        document.getElementById('quickForwardForm').reset();
        modal.show();
    }

    async createQuickForward() {
        const form = document.getElementById('quickForwardForm');
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        const rule = {
            name: `Forward to ${document.getElementById('targetInfo').value}`,
            external_port: parseInt(document.getElementById('quickExternalPort').value),
            internal_ip: document.getElementById('targetIP').value,
            internal_port: parseInt(document.getElementById('quickInternalPort').value),
            protocol: document.getElementById('quickProtocol').value,
            enabled: true,
        };

        try {
            const response = await this.makeRequest('/api/rules', {
                method: 'POST',
                body: JSON.stringify(rule),
            });

            if (response.success) {
                this.showAlert('Port forwarding rule created', 'success');
                bootstrap.Modal.getInstance(document.getElementById('quickForwardModal')).hide();
                this.loadRules();
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to create quick forward:', error);
        }
    }

    // Backup Management
    async loadBackups() {
        try {
            const response = await this.makeRequest('/api/backup/list');
            if (response.success) {
                this.updateBackupsTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load backups:', error);
        }
    }

    updateBackupsTable(backups) {
        const tbody = document.querySelector('#backups-table tbody');
        tbody.innerHTML = '';

        backups.forEach(backup => {
            const row = document.createElement('tr');
            const date = new Date(backup.timestamp).toLocaleString();
            const size = this.formatBytes(backup.file_size);
            
            row.innerHTML = `
                <td>${date}</td>
                <td>${backup.rules_count}</td>
                <td>${size}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="app.downloadBackup('${backup.timestamp}')">
                            <i class="bi bi-download"></i>
                        </button>
                        <button class="btn btn-outline-info" onclick="app.previewRestore('${backup.timestamp}')">
                            <i class="bi bi-eye"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="app.restoreBackup('${backup.timestamp}')">
                            <i class="bi bi-arrow-clockwise"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async createBackup() {
        const name = prompt('Enter backup name (optional):');
        if (name === null) return;

        try {
            const response = await this.makeRequest('/api/backup/create', {
                method: 'POST',
                body: JSON.stringify({ name: name || '' }),
            });

            if (response.success) {
                this.showAlert('Backup created successfully', 'success');
                this.loadBackups();
            }
        } catch (error) {
            console.error('Failed to create backup:', error);
        }
    }

    // Utility Functions
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alert-container');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        alertContainer.appendChild(alert);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                bootstrap.Alert.getOrCreateInstance(alert).close();
            }
        }, 5000);
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new NetNATApp();
});