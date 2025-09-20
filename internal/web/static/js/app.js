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
        this.updateDashboard();
        this.initTheme();
        
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
        document.getElementById('refresh-rules-btn').addEventListener('click', () => this.refreshRules());

        // VMs
        document.getElementById('refresh-vms-btn').addEventListener('click', () => this.refreshVMs());

        // Backup
        document.getElementById('create-backup-btn').addEventListener('click', () => this.createBackup());

        // Quick Forward
        document.getElementById('createQuickForward').addEventListener('click', () => this.createQuickForward());

        // Dark Mode Only (no toggle needed)

        // Remove this section since we're using onclick handlers now
    }

    initTheme() {
        // Always use dark mode
        document.documentElement.setAttribute('data-theme', 'dark');
        const themeIcon = document.getElementById('theme-icon');
        if (themeIcon) {
            themeIcon.className = 'bi bi-moon-fill';
        }
    }

    showLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.style.display = 'flex';
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }

    showAlert(message, type = 'info', duration = 5000) {
        const alertContainer = document.getElementById('alert-container');
        const alertId = 'alert-' + Date.now();
        
        const alertHTML = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                <i class="bi bi-${this.getAlertIcon(type)} me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        alertContainer.insertAdjacentHTML('beforeend', alertHTML);
        
        // Auto-remove after duration
        setTimeout(() => {
            const alert = document.getElementById(alertId);
            if (alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, duration);
    }

    getAlertIcon(type) {
        const icons = {
            'success': 'check-circle-fill',
            'danger': 'exclamation-triangle-fill',
            'warning': 'exclamation-triangle-fill',
            'info': 'info-circle-fill'
        };
        return icons[type] || 'info-circle-fill';
    }

    switchToTab(tabName) {
        // Hide all tab panes
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('show', 'active');
        });
        
        // Remove active class from all nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        // Show target tab pane
        const targetPane = document.getElementById(tabName);
        if (targetPane) {
            targetPane.classList.add('show', 'active');
        }
        
        // Add active class to clicked nav link
        const activeLink = document.querySelector(`[href="#${tabName}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }
        
        // Load data for specific tabs
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
            case 'dashboard':
                this.updateDashboard();
                break;
        }
    }

    // CSRF Token Management
    async getCSRFToken() {
        try {
            const response = await fetch('/api/csrf-token');
            const data = await response.json();
            if (data.success) {
                this.csrfToken = data.data.token;
                console.log('CSRF token obtained:', this.csrfToken ? 'yes' : 'no');
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

        // Update dashboard summary
        this.updateDashboard();
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
        this.showLoading('rules');
        try {
            const response = await this.makeRequest('/api/rules');
            if (response.success) {
                this.updateRulesTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load rules:', error);
            this.updateRulesTable([]);
        } finally {
            this.hideLoading('rules');
        }
    }

    // Enhanced refresh with cleanup functionality
    async refreshRules() {
        this.showLoading('rules');
        try {
            // First perform cleanup and validation
            const cleanupResponse = await this.makeRequest('/api/rules/cleanup', { method: 'POST' });
            if (cleanupResponse.success) {
                const result = cleanupResponse.data;
                
                // Show cleanup results
                let message = cleanupResponse.message;
                if (result.duplicates_removed > 0 || result.validation_result.fixed_rules > 0) {
                    message += '\n\nDetails:';
                    if (result.duplicates_removed > 0) {
                        message += `\n• Removed ${result.duplicates_removed} duplicate port rules`;
                    }
                    if (result.validation_result.fixed_rules > 0) {
                        message += `\n• Fixed ${result.validation_result.fixed_rules} rule issues`;
                    }
                    if (result.validation_result.warnings.length > 0) {
                        message += `\n• ${result.validation_result.warnings.length} warnings addressed`;
                    }
                    
                    this.showAlert(message, 'info', 8000);
                } else {
                    this.showAlert('Rules refreshed - no issues found', 'success');
                }
            }
            
            // Then reload rules
            await this.loadRules();
            await this.loadSystemStatus();
            
        } catch (error) {
            console.error('Failed to refresh rules:', error);
            // Fallback to simple reload if cleanup fails
            this.showAlert('Cleanup failed, performing simple refresh', 'warning');
            await this.loadRules();
        } finally {
            this.hideLoading('rules');
        }
    }

    updateRulesTable(rules) {
        const tbody = document.querySelector('#rules-table tbody');
        tbody.innerHTML = '';

        if (!rules || !Array.isArray(rules)) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No rules available</td></tr>';
            return;
        }

        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No port forwarding rules found</td></tr>';
            return;
        }

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
        
        // Update dashboard summary
        this.updateDashboard();
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

        // Refresh CSRF token before making the request
        await this.getCSRFToken();

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
        this.showLoading('vms');
        try {
            const response = await this.makeRequest('/api/vms');
            if (response.success) {
                this.updateVMsTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load VMs:', error);
            this.updateVMsTable([]);
        } finally {
            this.hideLoading('vms');
        }
    }

    updateVMsTable(vms) {
        const tbody = document.querySelector('#vms-table tbody');
        tbody.innerHTML = '';

        if (!vms || !Array.isArray(vms)) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No VMs/CTs available</td></tr>';
            return;
        }

        if (vms.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No VMs/CTs found</td></tr>';
            return;
        }

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
        
        // Update dashboard summary
        this.updateDashboard();
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
        document.getElementById('targetInfo').value = `${name} (${vmId}) - ${ip}`;
        document.getElementById('targetIP').value = ip;
        modal.show();
    }
    
    showQuickForwardModal() {
        // Simple modal without pre-selection - user can manually enter IP
        const modal = new bootstrap.Modal(document.getElementById('quickForwardModal'));
        document.getElementById('quickForwardForm').reset();
        document.getElementById('targetInfo').value = 'Manual Entry';
        modal.show();
    }

    async createQuickForward() {
        const form = document.getElementById('quickForwardForm');
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        const targetInfo = document.getElementById('targetInfo').value;
        const targetIP = document.getElementById('targetIP').value;
        const externalPort = document.getElementById('quickExternalPort').value;
        const internalPort = document.getElementById('quickInternalPort').value;
        const protocol = document.getElementById('quickProtocol').value.toUpperCase();
        
        // Validate target IP
        if (!targetIP || targetIP.trim() === '') {
            this.showAlert('Please select a valid VM/CT or enter target IP manually', 'warning');
            return;
        }
        
        // Create a descriptive rule name based on available info
        let ruleName;
        if (targetInfo === 'Manual Entry') {
            ruleName = `Forward to ${targetIP} - ${protocol}:${externalPort}→${internalPort}`;
        } else {
            ruleName = `${targetInfo} - ${protocol}:${externalPort}→${internalPort}`;
        }

        const rule = {
            name: ruleName,
            external_port: parseInt(externalPort),
            internal_ip: targetIP,
            internal_port: parseInt(internalPort),
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

    // Orphaned Rules Management
    async detectOrphanedRules() {
        try {
            const response = await this.makeRequest('/api/rules/orphaned');
            if (response.success) {
                const result = response.data;
                
                if (result.orphaned_rules && result.orphaned_rules.length > 0) {
                    let message = `Found ${result.orphaned_rules.length} orphaned rule(s):\n\n`;
                    result.orphaned_rules.slice(0, 5).forEach(rule => {
                        message += `• ${rule.name}: ${rule.external_port}/${rule.protocol} → ${rule.internal_ip}:${rule.internal_port}\n`;
                    });
                    
                    if (result.orphaned_rules.length > 5) {
                        message += `... and ${result.orphaned_rules.length - 5} more rules\n`;
                    }
                    
                    message += '\nThese rules point to VMs/CTs that no longer exist. Would you like to remove them?';
                    
                    if (confirm(message)) {
                        await this.cleanOrphanedRules();
                    }
                } else {
                    this.showAlert('No orphaned rules found', 'success');
                }
            }
        } catch (error) {
            console.error('Failed to detect orphaned rules:', error);
        }
    }

    async cleanOrphanedRules() {
        try {
            const response = await this.makeRequest('/api/rules/orphaned/cleanup', { method: 'POST' });
            if (response.success) {
                this.showAlert(response.message, 'success');
                this.loadRules();
                this.loadSystemStatus();
            }
        } catch (error) {
            console.error('Failed to clean orphaned rules:', error);
        }
    }

    // Backup Management
    async loadBackups() {
        this.showLoading('backups');
        try {
            const response = await this.makeRequest('/api/backup/list');
            if (response.success) {
                this.updateBackupsTable(response.data);
            }
        } catch (error) {
            console.error('Failed to load backups:', error);
            this.updateBackupsTable([]);
        } finally {
            this.hideLoading('backups');
        }
    }

    updateBackupsTable(backups) {
        const tbody = document.querySelector('#backups-table tbody');
        tbody.innerHTML = '';

        if (!backups || !Array.isArray(backups)) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No backups available</td></tr>';
            return;
        }

        if (backups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No backups found</td></tr>';
            return;
        }

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

    async downloadBackup(timestamp) {
        try {
            window.open(`/api/backup/export/${timestamp}`, '_blank');
        } catch (error) {
            console.error('Failed to download backup:', error);
            this.showAlert('Failed to download backup', 'danger');
        }
    }

    async previewRestore(timestamp) {
        try {
            const response = await this.makeRequest('/api/backup/restore', {
                method: 'POST',
                body: JSON.stringify({
                    backup_path: `${timestamp}`,
                    preview: true
                }),
            });

            if (response.success) {
                const preview = response.data;
                let message = `Restore Preview:\n\n`;
                message += `Rules to be restored: ${preview.rules_count || 0}\n`;
                message += `Current rules will be replaced: ${preview.current_rules_count || 0}\n\n`;
                
                if (preview.rules && preview.rules.length > 0) {
                    message += `Rules that will be added:\n`;
                    preview.rules.slice(0, 5).forEach(rule => {
                        message += `- ${rule.name}: ${rule.external_port}/${rule.protocol} → ${rule.internal_ip}:${rule.internal_port}\n`;
                    });
                    if (preview.rules.length > 5) {
                        message += `... and ${preview.rules.length - 5} more rules\n`;
                    }
                } else {
                    message += `No rules in this backup.\n`;
                }
                
                alert(message);
            }
        } catch (error) {
            console.error('Failed to preview restore:', error);
        }
    }

    async restoreBackup(timestamp) {
        if (!confirm('Are you sure you want to restore this backup? This will replace all current rules and cannot be undone.')) {
            return;
        }

        try {
            const response = await this.makeRequest('/api/backup/restore', {
                method: 'POST',
                body: JSON.stringify({
                    backup_path: `${timestamp}`,
                    preview: false
                }),
            });

            if (response.success) {
                this.showAlert('Backup restored successfully', 'success');
                this.loadRules();
                this.loadSystemStatus();
                this.loadBackups();
            }
        } catch (error) {
            console.error('Failed to restore backup:', error);
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
    
    // Loading Animation
    showLoading(section) {
        const loadingRow = document.getElementById(`${section}-loading`);
        if (loadingRow) {
            loadingRow.style.display = '';
        }
    }
    
    hideLoading(section) {
        const loadingRow = document.getElementById(`${section}-loading`);
        if (loadingRow) {
            loadingRow.style.display = 'none';
        }
    }
    
    // Dashboard Summary Updates
    updateDashboard() {
        this.updateVMSummary();
        this.updateRecentRules();
        this.updateVMDiscoverySummary();
    }
    
    updateVMSummary() {
        // This will be called after VM data is loaded
        const vmsTable = document.querySelector('#vms-table tbody');
        if (!vmsTable) return;
        
        const vmRows = vmsTable.querySelectorAll('tr');
        let totalVMs = 0;
        let runningVMs = 0;
        let vmsWithIP = 0;
        
        vmRows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 5 && !row.textContent.includes('No VMs/CTs')) {
                totalVMs++;
                
                // Check if running
                const statusCell = cells[4];
                if (statusCell && statusCell.textContent.toLowerCase().includes('running')) {
                    runningVMs++;
                }
                
                // Check if has IP
                const ipCell = cells[3];
                if (ipCell && ipCell.textContent.trim() !== '-' && ipCell.textContent.trim() !== '') {
                    vmsWithIP++;
                }
            }
        });
        
        // Update summary numbers
        document.getElementById('total-vms').textContent = totalVMs;
        document.getElementById('running-vms').textContent = runningVMs;
        document.getElementById('vms-with-ip').textContent = vmsWithIP;
        
        // Update recent VMs list (show first 3)
        const recentVMsContainer = document.getElementById('recent-vms');
        recentVMsContainer.innerHTML = '';
        
        let count = 0;
        vmRows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 4 && !row.textContent.includes('No VMs/CTs') && count < 3) {
                const vmId = cells[0].textContent;
                const vmName = cells[1].textContent || 'Unnamed';
                const vmType = cells[2].textContent;
                const vmIP = cells[3].textContent.trim();
                
                const vmItem = document.createElement('div');
                vmItem.className = 'small border-bottom pb-1 mb-1';
                vmItem.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <span><strong>${vmId}</strong> ${vmName.substring(0, 15)}${vmName.length > 15 ? '...' : ''}</span>
                        <span class="badge badge-sm ${vmType.toLowerCase().includes('qemu') ? 'bg-primary' : 'bg-info'}">${vmType}</span>
                    </div>
                    <div class="text-muted"><code>${vmIP !== '-' ? vmIP : 'No IP'}</code></div>
                `;
                recentVMsContainer.appendChild(vmItem);
                count++;
            }
        });
        
        if (count === 0) {
            recentVMsContainer.innerHTML = '<small class="text-muted">No VMs/CTs found</small>';
        }
    }
    
    updateRecentRules() {
        const rulesTable = document.querySelector('#rules-table tbody');
        if (!rulesTable) return;
        
        const recentRulesContainer = document.getElementById('recent-rules');
        recentRulesContainer.innerHTML = '';
        
        const ruleRows = rulesTable.querySelectorAll('tr');
        let count = 0;
        
        ruleRows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 6 && !row.textContent.includes('No port forwarding') && count < 5) {
                const ruleName = cells[0].textContent;
                const externalPort = cells[1].textContent;
                const internalIP = cells[2].textContent;
                const internalPort = cells[3].textContent;
                const protocol = cells[4].textContent;
                const enabled = cells[5].querySelector('.badge').textContent.toLowerCase().includes('enabled');
                
                const ruleItem = document.createElement('div');
                ruleItem.className = 'small border-bottom pb-1 mb-1';
                ruleItem.innerHTML = `
                    <div class="d-flex justify-content-between align-items-center">
                        <span><strong>${ruleName.substring(0, 20)}${ruleName.length > 20 ? '...' : ''}</strong></span>
                        <span class="badge badge-sm ${enabled ? 'bg-success' : 'bg-secondary'}">${enabled ? 'ON' : 'OFF'}</span>
                    </div>
                    <div class="text-muted">
                        <code>${externalPort}/${protocol.toLowerCase()}</code> →
                        <code>${internalIP}:${internalPort}</code>
                    </div>
                `;
                recentRulesContainer.appendChild(ruleItem);
                count++;
            }
        });
        
        if (count === 0) {
            recentRulesContainer.innerHTML = '<small class="text-muted">No port forwarding rules</small>';
        }
    }
    
    updateVMDiscoverySummary() {
        const vmsTable = document.querySelector('#vms-table tbody');
        const discoveryContainer = document.getElementById('vm-discovery-summary');
        
        if (!vmsTable || !discoveryContainer) return;
        
        const vmRows = vmsTable.querySelectorAll('tr');
        
        let qemuAgent = 0;
        let lxcConfig = 0;
        let arpTable = 0;
        let manual = 0;
        let totalVMs = 0;
        
        vmRows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 6 && !row.textContent.includes('No VMs/CTs') && !row.textContent.includes('Loading')) {
                totalVMs++;
                const sourceText = cells[5].textContent.trim().toLowerCase();
                
                // More specific matching for discovery sources
                if (sourceText.includes('qemu') || sourceText.includes('agent')) {
                    qemuAgent++;
                } else if (sourceText.includes('lxc') || sourceText.includes('container')) {
                    lxcConfig++;
                } else if (sourceText.includes('arp') || sourceText.includes('network')) {
                    arpTable++;
                } else if (sourceText.includes('manual') || sourceText.includes('config')) {
                    manual++;
                } else {
                    // Default to manual if unknown source
                    manual++;
                }
            }
        });
        
        // Create summary display
        discoveryContainer.innerHTML = `
            <div class="row text-center">
                <div class="col-6 mb-2">
                    <div class="border rounded p-2 ${qemuAgent > 0 ? 'bg-light' : ''}">
                        <div class="h6 mb-0 ${qemuAgent > 0 ? 'text-primary' : 'text-muted'}">${qemuAgent}</div>
                        <small class="text-muted">QEMU Agent</small>
                    </div>
                </div>
                <div class="col-6 mb-2">
                    <div class="border rounded p-2 ${lxcConfig > 0 ? 'bg-light' : ''}">
                        <div class="h6 mb-0 ${lxcConfig > 0 ? 'text-info' : 'text-muted'}">${lxcConfig}</div>
                        <small class="text-muted">LXC Config</small>
                    </div>
                </div>
                <div class="col-6">
                    <div class="border rounded p-2 ${arpTable > 0 ? 'bg-light' : ''}">
                        <div class="h6 mb-0 ${arpTable > 0 ? 'text-warning' : 'text-muted'}">${arpTable}</div>
                        <small class="text-muted">ARP Table</small>
                    </div>
                </div>
                <div class="col-6">
                    <div class="border rounded p-2 ${manual > 0 ? 'bg-light' : ''}">
                        <div class="h6 mb-0 ${manual > 0 ? 'text-secondary' : 'text-muted'}">${manual}</div>
                        <small class="text-muted">Manual</small>
                    </div>
                </div>
            </div>
            ${totalVMs > 0 ? `<div class="text-center mt-2"><small class="text-muted">Total: ${totalVMs} VMs/CTs discovered</small></div>` : ''}
        `;
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new NetNATApp();
});