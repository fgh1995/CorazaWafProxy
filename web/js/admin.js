let availableRules = [];
let wafInstances = [];
let proxyInstances = [];
let domainRules = [];
let portForwardInstances = [];
let certificates = [];
let currentEditWAFId = null;
let currentEditProxyId = null;
let currentEditPortForwardId = null;
let currentEditCertId = null;
let confirmCallback = null;
let statsData = {
    requestCount: 0,
    pv: 0,
    uv: 0,
    uniqueIP: 0,
    blockedCount: 0,
    attackIP: 0,
    qps: 0,
    avgResponseTime: 0,
    pvPeak: 0,
    blockPeak: 0,
    geoDistribution: {}
};
let currentGeoTab = 'world';
let currentActionTab = 'access';
let historyData = {
    qpsHistory: [],
    attackHistory: [],
    trafficHistory: [],
    trafficStats: {
        inboundBytes: 0,
        outboundBytes: 0,
        inboundRate: 0,
        outboundRate: 0
    }
};

let qpsHighlightIndex = -1;
let qpsBars = [];
let tooltipElement = null;
let geoMapChartChina = null;
let geoMapChartWorld = null;
let qpsChart = null;
let currentUsername = '';
let isLoggedIn = false;
let currentLogsPage = 1;
let totalLogsPages = 1;
let currentLogsPageSize = 20;
let fullClientStats = null;
let top5ClientStats = null;

async function loadCurrentUser() {
    try {
        const response = await fetch('/api/current-user');
        const result = await response.json();
        
        if (result.success && result.username) {
            currentUsername = result.username;
            isLoggedIn = true;
            const usernameElement = document.getElementById('current-username');
            if (usernameElement) {
                usernameElement.textContent = result.username;
            }
            const settingsUsernameElement = document.getElementById('settings-current-username');
            if (settingsUsernameElement) {
                settingsUsernameElement.value = result.username;
            }
            
            await checkAndUpgradeDatabase();
        } else {
            isLoggedIn = false;
            const usernameElement = document.getElementById('current-username');
            if (usernameElement) {
                usernameElement.textContent = '未登录';
            }
        }
        updateUIBasedOnLoginStatus();
    } catch (error) {
        console.error('加载用户信息失败:', error);
        isLoggedIn = false;
        const usernameElement = document.getElementById('current-username');
        if (usernameElement) {
            usernameElement.textContent = '未登录';
        }
        updateUIBasedOnLoginStatus();
    }
}

function updateUIBasedOnLoginStatus() {
    const logoutBtn = document.querySelector('.logout-btn');
    const logoutText = logoutBtn ? logoutBtn.querySelector('span:last-child') : null;
    const loginWarning = document.getElementById('login-warning');
    
    if (isLoggedIn) {
        if (logoutText) {
            logoutText.textContent = '退出登录';
        }
        if (loginWarning) {
            loginWarning.style.display = 'none';
        }
        enableAllModifyButtons();
    } else {
        if (logoutText) {
            logoutText.textContent = '登录';
        }
        if (loginWarning) {
            loginWarning.style.display = 'block';
        }
        disableAllModifyButtons();
    }
}

function disableAllModifyButtons() {
    const buttons = document.querySelectorAll('button[onclick*="save"], button[onclick*="delete"], button[onclick*="edit"], button[onclick*="add"], button[onclick*="create"], button[onclick*="import"]');
    buttons.forEach(btn => {
        btn.disabled = true;
        btn.style.opacity = '0.5';
        btn.style.cursor = 'not-allowed';
    });
    
    const inputs = document.querySelectorAll('input:not([disabled]), select:not([disabled])');
    inputs.forEach(input => {
        const id = input.id.toLowerCase();
        if (!id.includes('filter') && !id.includes('search') && !id.includes('page')) {
            input.disabled = true;
            input.style.opacity = '0.7';
        }
    });
}

function enableAllModifyButtons() {
    const buttons = document.querySelectorAll('button[onclick*="save"], button[onclick*="delete"], button[onclick*="edit"], button[onclick*="add"], button[onclick*="create"], button[onclick*="import"]');
    buttons.forEach(btn => {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
    });
    
    const inputs = document.querySelectorAll('input[disabled], select[disabled]');
    inputs.forEach(input => {
        const id = input.id.toLowerCase();
        if (!id.includes('settings-current-') && !id.includes('filter') && !id.includes('search') && !id.includes('page')) {
            input.disabled = false;
            input.style.opacity = '1';
        }
    });
}

async function loadSystemSettings() {
    try {
        const response = await fetch('/api/system-settings');
        const result = await response.json();
        
        if (result.success && result.adminPort) {
            const adminPortElement = document.getElementById('settings-current-admin-port');
            if (adminPortElement) {
                adminPortElement.value = result.adminPort;
            }
        }

        await loadWebhookSettings();
    } catch (error) {
        console.error('加载系统设置失败:', error);
    }
}

async function loadWebhookSettings() {
    try {
        const response = await fetch('/api/webhook-settings');
        const result = await response.json();
        
        if (result.success && result.data) {
            const data = result.data;
            document.getElementById('webhook-enabled').checked = data.enabled;
            document.getElementById('webhook-url').value = data.url || '';
            document.getElementById('webhook-timeout').value = data.timeout || 5;
            
            const events = (data.events || '').split(',');
            document.getElementById('webhook-event-attack').checked = events.includes('attack');
            document.getElementById('webhook-event-ip-blocked').checked = events.includes('ip_blocked');
        }
    } catch (error) {
        console.error('加载Webhook设置失败:', error);
    }
}

async function saveWebhookSettings() {
    const enabled = document.getElementById('webhook-enabled').checked;
    const url = document.getElementById('webhook-url').value.trim();
    const timeout = parseInt(document.getElementById('webhook-timeout').value) || 5;
    
    const events = [];
    if (document.getElementById('webhook-event-attack').checked) {
        events.push('attack');
    }
    if (document.getElementById('webhook-event-ip-blocked').checked) {
        events.push('ip_blocked');
    }
    
    if (enabled && !url) {
        showAlert('错误', '启用Webhook时必须填写URL');
        return;
    }
    
    if (timeout < 1 || timeout > 60) {
        showAlert('错误', '超时时间必须在1-60秒之间');
        return;
    }
    
    try {
        const response = await fetch('/api/webhook-settings', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                enabled: enabled,
                url: url,
                events: events.join(','),
                timeout: timeout
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('成功', result.message || 'Webhook配置已保存');
        } else {
            showAlert('错误', result.error || '保存失败');
        }
    } catch (error) {
        console.error('保存Webhook设置失败:', error);
        showAlert('错误', '保存Webhook设置失败');
    }
}

async function testWebhook() {
    const url = document.getElementById('webhook-url').value.trim();
    if (!url) {
        showAlert('错误', '请先配置Webhook URL');
        return;
    }

    try {
        const response = await fetch('/api/webhook-settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const result = await response.json();

        if (result.success) {
            showAlert('成功', result.message + '<br>状态码: ' + result.statusCode + '<br>响应: ' + (result.responseBody || '无'));
        } else {
            showAlert('错误', result.error + '<br>状态码: ' + (result.statusCode || '无') + '<br>响应: ' + (result.responseBody || '无'));
        }
    } catch (error) {
        console.error('测试Webhook失败:', error);
        showAlert('错误', '测试Webhook失败: ' + error.message);
    }
}

async function saveAdminPort() {
    const newPort = document.getElementById('settings-new-admin-port').value;
    
    if (!newPort) {
        showAlert('错误', '请输入新端口');
        return;
    }
    
    const portNum = parseInt(newPort);
    if (portNum < 1024 || portNum > 65535) {
        showAlert('错误', '端口必须在1024-65535之间');
        return;
    }
    
    showConfirm('确定要修改管理端口吗？修改后服务将自动重启，请使用新端口重新访问管理界面。', async (result) => {
        if (!result) {
            return;
        }
        
        try {
            const response = await fetch('/api/system-settings', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    adminPort: newPort
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                document.getElementById('settings-new-admin-port').value = '';
                
                let countdown = 3;
                const alertTitle = document.getElementById('alertTitle');
                const alertMessage = document.getElementById('alertMessage');
                
                alertTitle.textContent = '成功';
                alertMessage.innerHTML = `${result.message || '管理端口修改成功，服务即将重启...'}<br><br><span id="countdown" style="font-size: 18px; font-weight: bold;">${countdown}</span> 秒后自动跳转到新端口...`;
                document.getElementById('alertModal').classList.remove('modal-hidden');
                
                const countdownInterval = setInterval(() => {
                    countdown--;
                    const countdownElement = document.getElementById('countdown');
                    if (countdownElement) {
                        countdownElement.textContent = countdown;
                    }
                    
                    if (countdown <= 0) {
                        clearInterval(countdownInterval);
                        const currentHost = window.location.hostname;
                        const newUrl = `http://${currentHost}:${newPort}/admin.html`;
                        window.location.href = newUrl;
                    }
                }, 1000);
            } else {
                showAlert('错误', result.error || '修改失败');
            }
        } catch (error) {
            console.error('修改管理端口失败:', error);
            showAlert('错误', '修改失败，请稍后重试');
        }
    });
}

async function saveSettings() {
    const oldPassword = document.getElementById('settings-old-password').value;
    const newPassword = document.getElementById('settings-new-password').value;
    const confirmPassword = document.getElementById('settings-confirm-password').value;
    const newUsername = document.getElementById('settings-new-username').value;
    
    if (!oldPassword) {
        showAlert('错误', '请输入原密码');
        return;
    }
    
    if (!newPassword) {
        showAlert('错误', '请输入新密码');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showAlert('错误', '两次输入的新密码不一致');
        return;
    }
    
    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                oldPassword: oldPassword,
                newPassword: newPassword,
                newUsername: newUsername
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('成功', '账户信息修改成功！');
            document.getElementById('settings-old-password').value = '';
            document.getElementById('settings-new-password').value = '';
            document.getElementById('settings-confirm-password').value = '';
            document.getElementById('settings-new-username').value = '';
            await loadCurrentUser();
        } else {
            showAlert('错误', result.error || '修改失败');
        }
    } catch (error) {
        console.error('修改账户信息失败:', error);
        showAlert('错误', '修改失败，请稍后重试');
    }
}

function formatUTCTimeToLocal(utcTimeString) {
    if (!utcTimeString) return '';
    
    let date;
    
    const timeStr = String(utcTimeString).trim();
    
    if (/^\d+$/.test(timeStr)) {
        const timestamp = parseInt(timeStr, 10);
        if (timestamp > 100000000000) {
            date = new Date(timestamp);
        } else {
            date = new Date(timestamp * 1000);
        }
    } else if (timeStr.includes('T')) {
        date = new Date(timeStr);
    } else {
        date = new Date(timeStr.replace(' ', 'T') + 'Z');
    }
    
    if (isNaN(date.getTime())) return utcTimeString;
    
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

function formatTime(timestamp) {
    if (!timestamp) return '未知';
    const num = typeof timestamp === 'string' ? parseInt(timestamp) : timestamp;
    if (isNaN(num)) return '未知';
    const date = new Date(num >= 1e12 ? num : num * 1000);
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d} ${h}:${min}:${s}`;
}

function showAlert(title, message) {
    document.getElementById('alertTitle').textContent = title;
    document.getElementById('alertMessage').textContent = message;
    document.getElementById('alertModal').classList.remove('modal-hidden');
}

function showUpgradeModal() {
    document.getElementById('upgradeModal').classList.remove('modal-hidden');
}

function closeUpgradeModal() {
    document.getElementById('upgradeModal').classList.add('modal-hidden');
    location.reload();
}

function setUpgradeStep(stepId, status) {
    const step = document.getElementById(stepId);
    if (step) {
        if (status === 'done') {
            step.innerHTML = '✓ ' + step.textContent.substring(2);
            step.style.color = 'var(--success-green)';
        } else if (status === 'current') {
            step.style.color = 'var(--primary-blue)';
            step.style.fontWeight = '600';
        } else {
            step.style.color = 'var(--text-muted)';
            step.style.fontWeight = 'normal';
        }
    }
}

function setUpgradeProgress(percent, message) {
    const progressBar = document.getElementById('upgradeProgressBar');
    const progressText = document.getElementById('upgradeProgressText');
    const upgradeMessage = document.getElementById('upgradeMessage');
    
    if (progressBar) progressBar.style.width = percent + '%';
    if (progressText) progressText.textContent = percent + '%';
    if (upgradeMessage) upgradeMessage.textContent = message;
}

async function checkAndUpgradeDatabase() {
    try {
        const response = await fetch('/api/db-version');
        const result = await response.json();
        
        if (result.success && result.needUpgrade) {
            showUpgradeModal();
            await performDatabaseUpgrade();
        }
    } catch (error) {
        console.error('检查数据库版本失败:', error);
    }
}

async function pollUpgradeProgress() {
    return new Promise((resolve, reject) => {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/db-upgrade-progress');
                const result = await response.json();
                
                if (!result.success) {
                    clearInterval(pollInterval);
                    reject(new Error(result.error || '查询进度失败'));
                    return;
                }
                
                const total = result.total || 1;
                const current = result.current || 0;
                const percent = Math.round((current / total) * 100);
                
                setUpgradeProgress(percent, result.step || '处理中...');
                
                if (result.completed) {
                    clearInterval(pollInterval);
                    resolve(result);
                    return;
                }
                
                if (result.stage === 'completed') {
                    clearInterval(pollInterval);
                    resolve(result);
                }
            } catch (error) {
                clearInterval(pollInterval);
                reject(error);
            }
        }, 500);
    });
}

async function performDatabaseUpgrade() {
    try {
        setUpgradeStep('stepCheck', 'current');
        setUpgradeProgress(5, '正在检查数据库版本...');
        
        const versionResponse = await fetch('/api/db-version');
        const versionResult = await versionResponse.json();
        
        if (!versionResult.success || !versionResult.needUpgrade) {
            setUpgradeProgress(100, '数据库已是最新版本');
            setUpgradeStep('stepCheck', 'done');
            setUpgradeStep('stepComplete', 'done');
            enableUpgradeCloseBtn();
            return;
        }
        
        setUpgradeStep('stepCheck', 'done');
        setUpgradeStep('stepBackup', 'current');
        setUpgradeProgress(10, '正在准备升级数据...');
        
        const upgradeResponse = await fetch('/api/db-upgrade', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const upgradeResult = await upgradeResponse.json();
        
        if (!upgradeResult.success) {
            setUpgradeProgress(100, '升级失败: ' + (upgradeResult.error || '未知错误'));
            document.getElementById('upgradeIcon').textContent = '❌';
            document.getElementById('upgradeMessage').style.color = 'var(--danger-red)';
            setUpgradeStep('stepUpgrade', 'error');
            enableUpgradeCloseBtn();
            return;
        }
        
        setUpgradeStep('stepBackup', 'done');
        setUpgradeStep('stepUpgrade', 'current');
        
        try {
            const completedResult = await pollUpgradeProgress();

            if (completedResult.message && completedResult.message.includes('完成')) {
                setUpgradeProgress(100, '升级成功，页面将在6秒后刷新...');
                setUpgradeStep('stepUpgrade', 'done');
                setUpgradeStep('stepComplete', 'done');
                document.getElementById('upgradeIcon').textContent = '✅';
                document.getElementById('upgradeMessage').style.color = 'var(--danger-red)';
                setTimeout(() => location.reload(), 6000);
            } else {
                setUpgradeProgress(100, '升级成功，页面将在6秒后刷新...');
                setUpgradeStep('stepUpgrade', 'done');
                setUpgradeStep('stepComplete', 'done');
                document.getElementById('upgradeIcon').textContent = '✅';
                document.getElementById('upgradeMessage').style.color = 'var(--danger-red)';
                setTimeout(() => location.reload(), 6000);
            }
        } catch (pollError) {
            setUpgradeProgress(100, '升级成功，页面将在6秒后刷新...');
            setUpgradeStep('stepUpgrade', 'done');
            setUpgradeStep('stepComplete', 'done');
            document.getElementById('upgradeIcon').textContent = '✅';
            document.getElementById('upgradeMessage').style.color = 'var(--danger-red)';
            setTimeout(() => location.reload(), 6000);
            console.error('轮询进度失败:', pollError);
        }

        enableUpgradeCloseBtn();
        
    } catch (error) {
        console.error('数据库升级失败:', error);
        setUpgradeProgress(100, '升级失败: ' + error.message);
        document.getElementById('upgradeIcon').textContent = '❌';
        document.getElementById('upgradeMessage').style.color = 'var(--danger-red)';
        enableUpgradeCloseBtn();
    }
}

function enableUpgradeCloseBtn() {
    const btn = document.getElementById('upgradeCloseBtn');
    if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        btn.textContent = '完成';
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showTooltip(x, y, value, time) {
    if (!tooltipElement) {
        tooltipElement = document.createElement('div');
        tooltipElement.style.cssText = `
            position: fixed;
            background: rgba(255, 255, 255, 1);
            color: #1a73e8;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            z-index: 10000;
            border: 1px solid rgba(26, 115, 232, 0.5);
            box-shadow: 0 0 10px rgba(26, 115, 232, 0.3);
            white-space: pre-line;
        `;
        document.body.appendChild(tooltipElement);
    }
    
    tooltipElement.style.display = 'block';
    tooltipElement.textContent = `${value}\n时间: ${time}`;
    tooltipElement.style.left = `${x + 10}px`;
    tooltipElement.style.top = `${y - 40}px`;
}

function closeAlertModal() {
    document.getElementById('alertModal').classList.add('modal-hidden');
}

function showConfirm(message, callback) {
    document.getElementById('confirmMessage').textContent = message;
    confirmCallback = callback;
    document.getElementById('confirmModal').classList.remove('modal-hidden');
}

function closeConfirmModal(result) {
    document.getElementById('confirmModal').classList.add('modal-hidden');
    if (confirmCallback) {
        const callback = confirmCallback;
        confirmCallback = null;
        callback(result);
    }
}

async function loadAvailableRules() {
    try {
        const response = await fetch('/api/available-rules');
        const data = await response.json();
        
        if (data.success) {
            availableRules = data.rules;
        } else {
            console.error('加载规则失败:', data.error);
        }
    } catch (error) {
        console.error('加载规则失败:', error);
    }
}

async function loadWAFInstances() {
    try {
        const response = await fetch('/api/waf-instances');
        const data = await response.json();
        
        if (data.success) {
            wafInstances = data.instances || [];
            renderWAFInstances();
            renderProxyInstances();
        }
    } catch (error) {
        console.error('加载WAF实例失败:', error);
    }
}

async function loadProxyInstances() {
    try {
        const response = await fetch('/api/proxy-instances');
        const data = await response.json();
        
        if (data.success) {
            proxyInstances = data.instances || [];
            await loadDomainRules();
            renderProxyInstances();
        }
    } catch (error) {
        console.error('加载防护应用失败:', error);
    }
}

async function loadDomainRules() {
    try {
        const response = await fetch('/api/domain-rules');
        const data = await response.json();
        
        if (data.success) {
            domainRules = data.rules || [];
        }
    } catch (error) {
        console.error('加载域名规则失败:', error);
    }
}

function renderWAFInstances() {
    const container = document.getElementById('wafInstancesList');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (wafInstances.length === 0) {
        container.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 200px; color: var(--text-muted);">暂无 CorazaWAF 实例</div>';
        return;
    }
    
    wafInstances.forEach(instance => {
        const div = document.createElement('div');
        div.className = 'instance-item';
        
        const modeClass = instance.mode === 'On' ? 'blocking' : (instance.mode === 'DetectionOnly' ? 'detection' : 'off');
        const modeText = instance.mode === 'On' ? '拦截模式' : (instance.mode === 'DetectionOnly' ? '观察模式' : '关闭');
        
        div.innerHTML = `
            <div class="instance-header">
                <div class="instance-name">
                    <span>🛡️</span>
                    <span>${instance.name}</span>
                </div>
                <span class="instance-status ${modeClass}">${modeText}</span>
            </div>
            <div class="instance-grid">
                <div class="instance-grid-item">
                    <div class="instance-grid-label">实例 ID</div>
                    <div class="instance-grid-value">${instance.id}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">规则数量</div>
                    <div class="instance-grid-value">${instance.rules.length}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">创建时间</div>
                    <div class="instance-grid-value">${formatTime(instance.createdAt)}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">绑定应用</div>
                    <div class="instance-grid-value">${instance.boundProxyCount || 0} 个</div>
                </div>
            </div>
            <div class="instance-actions">
                <button class="btn-icon" onclick="editWAFInstance('${instance.id}')" title="编辑">✏️</button>
                <button class="btn-icon delete" onclick="deleteWAFInstance('${instance.id}')" title="删除">🗑️</button>
            </div>
        `;
        container.appendChild(div);
    });
}

function renderProxyInstances() {
    const container = document.getElementById('proxyInstancesList');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (proxyInstances.length === 0) {
        container.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 200px; color: var(--text-muted);">暂无防护应用实例</div>';
        return;
    }
    
    proxyInstances.forEach(instance => {
        const wafDisplay = instance.wafName || (instance.wafId ? '未绑定' : '未绑定');
        const tlsBadge = instance.tlsEnabled ? '<span class="instance-badge" style="background: rgba(52, 168, 83, 0.1); color: #34a853;">HTTPS</span>' : '';
        
        const instanceRules = domainRules.filter(r => r.proxyId === instance.id);
        
        let getRuleTypeDisplay = (rule) => {
            if (rule.ruleType === 'redirect') return '重定向';
            if (rule.ruleType === 'close') return '关闭连接';
            return '反向代理';
        };
        
        let rulesHtml = '';
        if (instanceRules.length > 0) {
            rulesHtml = instanceRules.map(rule => {
                let actionDisplay = rule.domain === '' || rule.isDefault ? '默认规则' : rule.domain.split('\n').join(', ');
                let targetDisplay = rule.ruleType === 'redirect' ? rule.redirectUrl : (rule.ruleType === 'close' ? '-' : (rule.backend || '-'));
                return `
                <tr style="transition: background 0.2s;">
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px;">${actionDisplay}</td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px;">${getRuleTypeDisplay(rule)}</td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px;">${targetDisplay}</td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e0e0e0; text-align: right; white-space: nowrap;">
                        <button class="btn-icon" style="font-size: 12px;" onclick="editDomainRule('${rule.id}')" title="编辑">✏️</button>
                        <button class="btn-icon" style="font-size: 12px;" onclick="deleteDomainRule('${rule.id}')" title="删除">🗑️</button>
                    </td>
                </tr>`;
            }).join('');
        } else {
            rulesHtml = '<tr><td colspan="4" style="padding: 12px; color: #999; text-align: center; font-size: 13px;">暂无域名规则</td></tr>';
        }
        
        const div = document.createElement('div');
        div.className = 'proxy-instance-card';

        div.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: #f5f7fa; border-bottom: 1px solid #e0e0e0;">
                <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                    <span style="font-weight: 600; font-size: 14px;">🌐 ${instance.name}</span>
                    <span class="instance-badge">端口: ${instance.listenPort}</span>
                    ${tlsBadge}
                    <span style="font-size: 13px; color: #666;">WAF: ${wafDisplay}</span>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn btn-primary" style="padding: 5px 12px; font-size: 12px;" onclick="openAddDomainRuleModal('${instance.id}')">+ 添加规则</button>
                    <button class="btn-icon" onclick="editProxyInstance('${instance.id}')" title="编辑">✏️</button>
                    <button class="btn-icon delete" onclick="deleteProxyInstance('${instance.id}')" title="删除">🗑️</button>
                </div>
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #fafafa;">
                        <th style="padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: #666; border-bottom: 1px solid #e0e0e0;">规则名称</th>
                        <th style="padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: #666; border-bottom: 1px solid #e0e0e0; width: 100px;">类型</th>
                        <th style="padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: #666; border-bottom: 1px solid #e0e0e0;">目标</th>
                        <th style="padding: 10px 14px; text-align: right; font-size: 12px; font-weight: 600; color: #666; border-bottom: 1px solid #e0e0e0; width: 90px;">操作</th>
                    </tr>
                </thead>
                <tbody>
                    ${rulesHtml}
                </tbody>
            </table>
        `;
        container.appendChild(div);
    });
}



async function openCreateWAFModal() {
    currentEditWAFId = null;
    document.getElementById('wafModalTitle').textContent = '创建 CorazaWAF';
    document.getElementById('wafEditName').value = '';
    document.getElementById('wafEditMode').value = 'On';
    renderWAFRulesList([]);
    document.getElementById('wafModal').classList.remove('modal-hidden');
}

async function editWAFInstance(id) {
    const instance = wafInstances.find(w => w.id === id);
    if (!instance) {
        showAlert('错误', 'WAF实例不存在');
        return;
    }

    currentEditWAFId = id;
    document.getElementById('wafModalTitle').textContent = '编辑 CorazaWAF';
    document.getElementById('wafEditName').value = instance.name;
    document.getElementById('wafEditMode').value = instance.mode;
    renderWAFRulesList(instance.rules);
    document.getElementById('wafModal').classList.remove('modal-hidden');
}

function renderWAFRulesList(selectedRules) {
    const container = document.getElementById('wafRulesList');
    if (!container) return;
    
    container.innerHTML = '';
    
    availableRules.forEach(rule => {
        const label = document.createElement('label');
        label.className = 'rule-item';
        label.innerHTML = `
            <input type="checkbox" class="rule-checkbox" value="${rule.code}" ${selectedRules.includes(rule.code) ? 'checked' : ''}>
            <strong>${rule.id}</strong> ${rule.name}
        `;
        container.appendChild(label);
    });
}

function closeWAFModal() {
    document.getElementById('wafModal').classList.add('modal-hidden');
    currentEditWAFId = null;
}

async function saveWAFEdit() {
    const name = document.getElementById('wafEditName').value;
    const mode = document.getElementById('wafEditMode').value;
    const selectedRules = Array.from(document.querySelectorAll('#wafRulesList .rule-checkbox:checked')).map(cb => cb.value);

    if (!name) {
        showAlert('提示', '请输入实例名称');
        return;
    }

    if (selectedRules.length === 0) {
        showAlert('提示', '请至少选择一个规则');
        return;
    }

    try {
        let response;
        if (currentEditWAFId) {
            response = await fetch(`/api/waf-instances/${currentEditWAFId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    mode: mode,
                    rules: selectedRules
                })
            });
        } else {
            response = await fetch('/api/waf-instances', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    mode: mode,
                    rules: selectedRules
                })
            });
        }

        const data = await response.json();

        if (data.success) {
            showAlert('成功', currentEditWAFId ? '更新成功' : '创建成功');
            closeWAFModal();
            await loadWAFInstances();
        } else {
            showAlert('错误', (currentEditWAFId ? '更新' : '创建') + '失败: ' + data.error);
        }
    } catch (error) {
        console.error('保存WAF实例失败:', error);
        showAlert('错误', (currentEditWAFId ? '更新' : '创建') + '失败');
    }
}

async function deleteWAFInstance(id) {
    showConfirm('确定要删除此WAF实例吗？', async (confirmed) => {
        if (!confirmed) return;
        
        try {
            const response = await fetch(`/api/waf-instances/${id}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert('成功', '删除成功');
                await loadWAFInstances();
            } else {
                showAlert('错误', '删除失败: ' + data.error);
            }
        } catch (error) {
            console.error('删除WAF实例失败:', error);
            showAlert('错误', '删除失败');
        }
    });
}

async function openCreateProxyModal() {
    currentEditProxyId = null;
    document.getElementById('proxyModalTitle').textContent = '创建防护应用';
    document.getElementById('proxyEditName').value = '';
    document.getElementById('proxyEditPort').value = '';
    document.getElementById('proxyEditBackend').value = '';
    document.getElementById('proxyEditFallbackBackend').value = '';
    document.getElementById('proxyEditTLSEnabled').checked = false;
    document.getElementById('proxyEditTLSCertFile').value = '';
    document.getElementById('proxyEditTLSKeyFile').value = '';
    document.getElementById('proxyEditCertId').value = '';
    toggleProxyTLSFields();

    document.getElementById('proxyBackendGroup').style.display = 'none';
    document.getElementById('proxyFallbackBackendGroup').style.display = 'none';

    const select = document.getElementById('proxyEditWAFId');
    select.innerHTML = '<option value="">不绑定 WAF</option>';
    wafInstances.forEach(waf => {
        const option = document.createElement('option');
        option.value = waf.id;
        option.textContent = waf.name;
        select.appendChild(option);
    });
    select.value = '';

    await loadCertificatesForSelect();
    document.getElementById('proxyModal').classList.remove('modal-hidden');
}

async function editProxyInstance(id) {
    const instance = proxyInstances.find(p => p.id === id);
    if (!instance) {
        showAlert('错误', '防护应用不存在');
        return;
    }

    currentEditProxyId = id;
    document.getElementById('proxyModalTitle').textContent = '编辑防护应用';
    document.getElementById('proxyEditName').value = instance.name;
    document.getElementById('proxyEditPort').value = instance.listenPort;
    document.getElementById('proxyEditBackend').value = instance.backend;
    document.getElementById('proxyEditFallbackBackend').value = instance.fallbackBackend || '';
    document.getElementById('proxyEditTLSEnabled').checked = instance.tlsEnabled || false;
    document.getElementById('proxyEditTLSCertFile').value = instance.tlsCertFile || '';
    document.getElementById('proxyEditTLSKeyFile').value = instance.tlsKeyFile || '';
    toggleProxyTLSFields();

    document.getElementById('proxyBackendGroup').style.display = 'none';
    document.getElementById('proxyFallbackBackendGroup').style.display = 'none';

    const select = document.getElementById('proxyEditWAFId');
    select.innerHTML = '<option value="">不绑定 WAF</option>';
    wafInstances.forEach(waf => {
        const option = document.createElement('option');
        option.value = waf.id;
        option.textContent = waf.name;
        select.appendChild(option);
    });
    select.value = instance.wafId || '';

    await loadCertificatesForSelect();
    document.getElementById('proxyModal').classList.remove('modal-hidden');
}

function toggleProxyTLSFields() {
    const enabled = document.getElementById('proxyEditTLSEnabled').checked;
    document.getElementById('proxyTLSFields').style.display = enabled ? 'block' : 'none';
}

function selectProxyCert() {
    const certId = document.getElementById('proxyEditCertId').value;
    if (certId) {
        const cert = certificates.find(c => c.id === certId);
        if (cert) {
            document.getElementById('proxyEditTLSCertFile').value = cert.certFile || '';
            document.getElementById('proxyEditTLSKeyFile').value = cert.keyFile || '';
        }
    }
}

async function loadCertificatesForSelect() {
    const select = document.getElementById('proxyEditCertId');
    if (!select) return;
    select.innerHTML = '<option value="">选择证书...</option>';
    certificates.forEach(cert => {
        const option = document.createElement('option');
        option.value = cert.id;
        option.textContent = `${cert.name} (${cert.domains})`;
        select.appendChild(option);
    });
}

function closeProxyModal() {
    document.getElementById('proxyModal').classList.add('modal-hidden');
    currentEditProxyId = null;
}

let currentDomainRuleProxyId = null;
let currentEditDomainRuleId = null;

function openAddDomainRuleModal(proxyId) {
    currentDomainRuleProxyId = proxyId;
    currentEditDomainRuleId = null;
    const proxy = proxyInstances.find(p => p.id === proxyId);
    if (!proxy) return;
    
    document.getElementById('domainRuleProxyId').value = proxyId;
    document.getElementById('domainRuleProxyName').textContent = proxy.name;
    document.getElementById('domainRuleModalTitle').textContent = '添加域名规则';
    document.getElementById('domainRuleSubmitBtn').textContent = '添加';
    document.getElementById('domainRuleDomain').value = '';
    document.getElementById('domainRuleBackend').value = '';
    document.getElementById('domainRuleType').value = 'proxy';
    document.getElementById('domainRuleRedirectUrl').value = '';
    document.getElementById('domainRuleEditId').value = '';
    
    document.getElementById('domainRuleDomainGroup').style.display = 'block';
    
    toggleDomainRuleFields();
    document.getElementById('domainRuleModal').classList.remove('modal-hidden');
}

function closeDomainRuleModal() {
    document.getElementById('domainRuleModal').classList.add('modal-hidden');
    currentDomainRuleProxyId = null;
    currentEditDomainRuleId = null;
}

async function addDomainRule() {
    if (!currentDomainRuleProxyId) return;
    
    const editId = document.getElementById('domainRuleEditId').value;
    const isEditing = editId !== '';
    const domain = document.getElementById('domainRuleDomain').value.trim();
    const backend = document.getElementById('domainRuleBackend').value.trim();
    const ruleType = document.getElementById('domainRuleType').value;
    const redirectUrl = document.getElementById('domainRuleRedirectUrl').value.trim();
    
    const rule = isEditing ? domainRules.find(r => r.id === editId) : null;
    const isDefaultRule = rule ? rule.isDefault : false;
    
    if (!isDefaultRule && !domain) {
        showAlert('提示', '请填写域名');
        return;
    }
    
    if (ruleType === 'proxy' && !backend) {
        showAlert('提示', '请填写后端地址');
        return;
    }
    
    if (ruleType === 'redirect' && !redirectUrl) {
        showAlert('提示', '请填写重定向URL');
        return;
    }
    
    try {
        const url = isEditing ? `/api/domain-rules` : '/api/domain-rules';
        const method = isEditing ? 'PUT' : 'POST';
        
        const requestBody = {
            proxyId: currentDomainRuleProxyId,
            domain: domain,
            backend: backend,
            isDefault: isDefaultRule,
            ruleType: ruleType,
            redirectUrl: redirectUrl
        };
        
        if (isEditing) {
            requestBody.id = editId;
        }
        
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        const data = await response.json();
        
        if (data.success) {
            closeDomainRuleModal();
            loadProxyInstances();
            showAlert('成功', isEditing ? '域名规则已更新' : '域名规则已添加');
        } else {
            showAlert('错误', data.error || '操作失败');
        }
    } catch (error) {
        console.error('操作域名规则失败:', error);
        showAlert('错误', error.message);
    }
}

async function editDomainRule(id) {
    currentEditDomainRuleId = id;
    const rule = domainRules.find(r => r.id === id);
    if (!rule) {
        showAlert('错误', '规则不存在');
        return;
    }
    
    currentDomainRuleProxyId = rule.proxyId;
    const proxy = proxyInstances.find(p => p.id === rule.proxyId);
    
    document.getElementById('domainRuleEditId').value = id;
    document.getElementById('domainRuleProxyId').value = rule.proxyId;
    document.getElementById('domainRuleProxyName').textContent = proxy ? proxy.name : '';
    document.getElementById('domainRuleModalTitle').textContent = '编辑域名规则';
    document.getElementById('domainRuleSubmitBtn').textContent = '保存';
    
    if (rule.isDefault) {
        document.getElementById('domainRuleDomainGroup').style.display = 'none';
        document.getElementById('domainRuleDomain').value = '';
    } else {
        document.getElementById('domainRuleDomainGroup').style.display = 'block';
        document.getElementById('domainRuleDomain').value = rule.domain || '';
    }
    
    document.getElementById('domainRuleBackend').value = rule.backend || '';
    document.getElementById('domainRuleType').value = rule.ruleType || 'proxy';
    document.getElementById('domainRuleRedirectUrl').value = rule.redirectUrl || '';
    
    toggleDomainRuleFields();
    document.getElementById('domainRuleModal').classList.remove('modal-hidden');
}

function toggleDomainRuleFields() {
    const ruleType = document.getElementById('domainRuleType').value;
    document.getElementById('domainRuleBackendGroup').style.display = ruleType === 'proxy' ? 'block' : 'none';
    document.getElementById('domainRuleRedirectUrlGroup').style.display = ruleType === 'redirect' ? 'block' : 'none';
}

async function deleteDomainRule(id) {
    showConfirm('确定要删除此域名规则吗？', async (confirmed) => {
        if (!confirmed) return;
        
        try {
            const response = await fetch(`/api/domain-rules/${id}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                loadProxyInstances();
                showAlert('成功', '域名规则已删除');
            } else {
                showAlert('错误', data.error || '删除失败');
            }
        } catch (error) {
            console.error('删除域名规则失败:', error);
            showAlert('错误', error.message);
        }
    });
}

async function saveProxyEdit() {
    const name = document.getElementById('proxyEditName').value;
    const listenPort = parseInt(document.getElementById('proxyEditPort').value);
    const backend = document.getElementById('proxyEditBackend').value;
    const fallbackBackend = document.getElementById('proxyEditFallbackBackend').value;
    const wafId = document.getElementById('proxyEditWAFId').value;
    const tlsEnabled = document.getElementById('proxyEditTLSEnabled').checked;
    const tlsCertFile = document.getElementById('proxyEditTLSCertFile').value;
    const tlsKeyFile = document.getElementById('proxyEditTLSKeyFile').value;

    if (!name || !listenPort) {
        showAlert('提示', '请填写名称和端口');
        return;
    }

    if (tlsEnabled && (!tlsCertFile || !tlsKeyFile)) {
        showAlert('提示', '启用HTTPS需要提供证书和私钥文件路径');
        return;
    }

    try {
        let response;
        if (currentEditProxyId) {
            response = await fetch(`/api/proxy-instances/${currentEditProxyId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    listenPort: listenPort,
                    backend: backend,
                    fallbackBackend: fallbackBackend,
                    wafId: wafId,
                    tlsEnabled: tlsEnabled,
                    tlsCertFile: tlsCertFile,
                    tlsKeyFile: tlsKeyFile
                })
            });
        } else {
            response = await fetch('/api/proxy-instances', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    listenPort: listenPort,
                    backend: backend,
                    fallbackBackend: fallbackBackend,
                    wafId: wafId,
                    tlsEnabled: tlsEnabled,
                    tlsCertFile: tlsCertFile,
                    tlsKeyFile: tlsKeyFile
                })
            });
        }

        const data = await response.json();

        if (data.success) {
            showAlert('成功', currentEditProxyId ? '更新成功' : '创建成功');
            closeProxyModal();
            await loadProxyInstances();
        } else {
            showAlert('错误', (currentEditProxyId ? '更新' : '创建') + '失败: ' + data.error);
        }
    } catch (error) {
        console.error('保存防护应用失败:', error);
        showAlert('错误', (currentEditProxyId ? '更新' : '创建') + '失败');
    }
}

async function deleteProxyInstance(id) {
    showConfirm('确定要删除此防护应用吗？', async (confirmed) => {
        if (!confirmed) return;
        
        try {
            const response = await fetch(`/api/proxy-instances/${id}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert('成功', '删除成功');
                await loadProxyInstances();
            } else {
                showAlert('错误', '删除失败: ' + data.error);
            }
        } catch (error) {
            console.error('删除防护应用失败:', error);
            showAlert('错误', '删除失败');
        }
    });
}

async function loadCertificates() {
    try {
        const response = await fetch('/api/certificates');
        const result = await response.json();

        if (result.success) {
            certificates = result.certificates || [];
            renderCertificates();
        }
    } catch (error) {
        console.error('加载证书失败:', error);
    }
}

function renderCertificates() {
    const container = document.getElementById('certInstancesList');
    if (!container) return;

    container.innerHTML = '';

    if (certificates.length === 0) {
        container.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 200px; color: var(--text-muted);">暂无证书，请点击"申请证书"创建</div>';
        return;
    }

    certificates.forEach(cert => {
        const div = document.createElement('div');
        div.className = 'instance-item';

        let statusClass = 'off';
        let statusText = '未知';

        if (cert.status === 'pending') {
            statusClass = 'breathing';
            statusText = '正在申请';
        } else if (cert.status === 'valid') {
            statusClass = 'running';
            statusText = '有效';
        } else if (cert.status === 'expired') {
            statusClass = 'off';
            statusText = '已过期';
        } else if (cert.status === 'failed') {
            statusClass = 'blocking';
            statusText = '失败';
        }

        const expiresAt = formatTime(cert.expiresAt);
        const autoRenewBadge = cert.autoRenew ? '<span class="instance-badge" style="background: rgba(52, 168, 83, 0.1); color: #34a853;">自动续期</span>' : '';

        div.innerHTML = `
            <div class="instance-header">
                <div class="instance-name">
                    <span>🔐</span>
                    <span>${cert.name}</span>
                </div>
                <span class="instance-status ${statusClass}">${statusText}</span>
                ${autoRenewBadge}
            </div>
            <div class="instance-grid">
                <div class="instance-grid-item">
                    <div class="instance-grid-label">域名</div>
                    <div class="instance-grid-value" style="position: relative; cursor: pointer;" onmouseover="this.querySelector('.domain-tooltip').style.display='block'" onmouseout="this.querySelector('.domain-tooltip').style.display='none'">
                        <span style="display: inline-block; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom;">${cert.domains.split(',')[0]}</span>${cert.domains.includes(',') ? '<span style="color: var(--primary-blue);"> (+' + (cert.domains.split(',').length - 1) + ')</span>' : ''}
                        <div class="domain-tooltip" style="display: none; position: absolute; top: 100%; left: 0; background: #fff; border: 1px solid var(--border-light); border-radius: 6px; padding: 8px 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 100; white-space: pre-line; font-size: 13px; min-width: 150px;">${cert.domains.replace(/,/g, '\n')}</div>
                    </div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">颁发机构</div>
                    <div class="instance-grid-value">${cert.provider}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">到期时间</div>
                    <div class="instance-grid-value">${expiresAt}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">证书文件</div>
                    <div class="instance-grid-value">${cert.certFile || '未设置'}</div>
                </div>
            </div>
            <div class="instance-actions">
                <button class="btn-icon" onclick="viewCertLogs('${cert.id}')" title="查看日志">📜</button>
                <button class="btn-icon" onclick="editCertificate('${cert.id}')" title="编辑">✏️</button>
                ${cert.status === 'pending' ? `<button class="btn-icon" onclick="stopCertificate('${cert.id}')" title="停止">⏹️</button>` : ''}
                ${cert.status === 'failed' ? `<button class="btn-icon" onclick="retryCertificate('${cert.id}')" title="重试">🔄</button>` : ''}
                ${cert.status === 'valid' ? `<button class="btn-icon" onclick="renewCertificate('${cert.id}')" title="续期">🔄</button>` : ''}
                <button class="btn-icon delete" onclick="deleteCertificate('${cert.id}')" title="删除">🗑️</button>
            </div>
        `;
        container.appendChild(div);
    });
}

function openCreateCertModal() {
    currentEditCertId = null;
    document.getElementById('certModalTitle').textContent = '申请证书';
    document.getElementById('certEditName').value = '';
    document.getElementById('certEditProvider').value = 'letsencrypt';
    document.getElementById('certEditZeroSSLEmail').value = '';
    document.getElementById('certEditAcmeEmail').value = '';
    document.getElementById('certEditCloudflareToken').value = '';
    document.getElementById('certEditDomains').value = '';
    document.getElementById('certEditAutoRenew').checked = true;
    document.getElementById('certApplyForm').style.display = 'block';
    document.getElementById('certLogContainer').style.display = 'none';
    document.getElementById('certModalApplyBtn').disabled = false;
    document.getElementById('certModalApplyBtn').textContent = '申请证书';
    toggleCertFields();
    document.getElementById('certModal').classList.remove('modal-hidden');
}

function closeCertModal() {
    document.getElementById('certModal').classList.add('modal-hidden');
    currentEditCertId = null;
}

function toggleCertFields() {
    const provider = document.getElementById('certEditProvider').value;
    const zerosslFields = document.getElementById('zerosslFields');
    const letsencryptFields = document.getElementById('letsencryptFields');

    if (provider === 'zerossl') {
        zerosslFields.style.display = 'block';
        letsencryptFields.style.display = 'none';
    } else {
        zerosslFields.style.display = 'none';
        letsencryptFields.style.display = 'block';
    }
}

async function applyCertificate() {
    const name = document.getElementById('certEditName').value;
    const provider = document.getElementById('certEditProvider').value;
    const cloudflareToken = document.getElementById('certEditCloudflareToken').value;
    const domainsText = document.getElementById('certEditDomains').value;
    const autoRenew = document.getElementById('certEditAutoRenew').checked;

    let acmeEmail = '';
    let acmeKid = '';
    let acmeHmacKey = '';
    let acmeServerURL = '';

    if (provider === 'zerossl') {
        acmeEmail = document.getElementById('certEditZeroSSLEmail').value;
        acmeServerURL = 'https://acme.zerossl.com/v2/DV90';
        if (!acmeEmail) {
            showAlert('提示', 'ZeroSSL 需要填写邮箱');
            return;
        }
    } else {
        acmeEmail = document.getElementById('certEditAcmeEmail').value;
        acmeServerURL = 'https://acme-v02.api.letsencrypt.org/directory';
    }

    if (!name || !domainsText || !cloudflareToken) {
        showAlert('提示', '请填写完整信息');
        return;
    }

    const domains = domainsText.split('\n').map(d => d.trim()).filter(d => d);

    if (domains.length === 0) {
        showAlert('提示', '请至少添加一个域名');
        return;
    }

    const applyForm = document.getElementById('certApplyForm');
    const logContainer = document.getElementById('certLogContainer');
    const logContent = document.getElementById('certLogContent');
    const applyBtn = document.getElementById('certModalApplyBtn');
    const cancelBtn = document.getElementById('certModalCancelBtn');

    if (!applyForm || !logContainer || !logContent || !applyBtn || !cancelBtn) {
        showAlert('错误', '页面元素缺失，请刷新重试');
        return;
    }

    applyForm.style.display = 'none';
    logContainer.style.display = 'block';
    logContent.textContent = '正在提交申请...\n';
    applyBtn.disabled = true;
    cancelBtn.textContent = '关闭';

    let logPollingInterval;

    async function pollLogs(certId) {
        try {
            const logContent = document.getElementById('certLogContent');
            if (!logContent || logContent.style.display === 'none') {
                clearInterval(logPollingInterval);
                return;
            }
            const response = await fetch(`/api/certificates/${certId}/logs`);
            const data = await response.json();
            if (data.success && data.logs) {
                logContent.textContent = data.logs.join('\n');
                logContent.scrollTop = logContent.scrollHeight;

                if (data.logs.some(log => log.includes('证书申请完成') || log.includes('证书申请失败'))) {
                    clearInterval(logPollingInterval);
                    setTimeout(() => {
                        const cancelBtn = document.getElementById('certModalCancelBtn');
                        const applyBtn = document.getElementById('certModalApplyBtn');
                        if (cancelBtn) cancelBtn.textContent = '关闭';
                        if (applyBtn) applyBtn.disabled = false;
                        if (data.logs.some(log => log.includes('证书申请完成'))) {
                            closeCertModal();
                            loadCertificates();
                        }
                    }, 2000);
                    return;
                }
            }
        } catch (error) {
            console.error('获取日志失败:', error);
        }
    }

    try {
        const isEditing = currentEditCertId !== null;
        const url = isEditing ? `/api/certificates/${currentEditCertId}` : '/api/certificates';
        const method = isEditing ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                provider: provider,
                domains: domains.join(','),
                autoRenew: autoRenew,
                cloudflareApiToken: cloudflareToken,
                acmeEmail: acmeEmail,
                acmeKid: acmeKid,
                acmeHmacKey: acmeHmacKey,
                acmeServerUrl: acmeServerURL
            })
        });

        const data = await response.json();

        if (data.success) {
            if (isEditing) {
                closeCertModal();
                loadCertificates();
                showAlert('成功', '证书信息已更新');
            } else {
                closeCertModal();
                loadCertificates();
            }
        } else {
            closeCertModal();
            showAlert('错误', data.error || '未知错误');
        }
    } catch (error) {
        console.error('证书申请失败:', error);
        closeCertModal();
        showAlert('错误', error.message);
    }
}

function viewCertDetail(id) {
    const cert = certificates.find(c => c.id === id);
    if (!cert) {
        showAlert('错误', '证书不存在');
        return;
    }

    const expiresAt = formatTime(cert.expiresAt);
    const createdAt = formatTime(cert.createdAt);

    const content = `
        <div style="display: grid; gap: 16px;">
            <div>
                <strong style="color: var(--text-secondary);">证书名称</strong>
                <div style="margin-top: 4px;">${cert.name}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">域名列表</strong>
                <div style="margin-top: 4px; white-space: pre-line;">${cert.domains}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">颁发机构</strong>
                <div style="margin-top: 4px;">${cert.provider}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">状态</strong>
                <div style="margin-top: 4px;">${cert.status}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">证书文件</strong>
                <div style="margin-top: 4px;">${cert.certFile || '未设置'}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">私钥文件</strong>
                <div style="margin-top: 4px;">${cert.keyFile || '未设置'}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">CA文件</strong>
                <div style="margin-top: 4px;">${cert.caFile || '未设置'}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">到期时间</strong>
                <div style="margin-top: 4px;">${expiresAt}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">创建时间</strong>
                <div style="margin-top: 4px;">${createdAt}</div>
            </div>
            <div>
                <strong style="color: var(--text-secondary);">自动续期</strong>
                <div style="margin-top: 4px;">${cert.autoRenew ? '已启用' : '未启用'}</div>
            </div>
        </div>
    `;

    document.getElementById('certDetailContent').innerHTML = content;
    document.getElementById('certDetailModal').classList.remove('modal-hidden');
}

function closeCertDetailModal() {
    document.getElementById('certDetailModal').classList.add('modal-hidden');
}

async function viewCertLogs(id) {
    try {
        const response = await fetch(`/api/certificates/${id}/logs`);
        const data = await response.json();

        if (data.success && data.logs) {
            const content = `
                <div style="margin-bottom: 16px;">
                    <strong style="color: var(--text-secondary);">申请日志</strong>
                    <div id="certLogViewContent" style="background: #1e1e1e; color: #00ff00; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin-top: 8px;">${data.logs.join('\n')}</div>
                </div>
            `;
            document.getElementById('certDetailContent').innerHTML = content;
            document.getElementById('certDetailModal').classList.remove('modal-hidden');

            const logContent = document.getElementById('certLogViewContent');
            logContent.scrollTop = logContent.scrollHeight;
        } else {
            showAlert('错误', '获取日志失败');
        }
    } catch (error) {
        console.error('获取日志失败:', error);
        showAlert('错误', error.message);
    }
}

function editCertificate(id) {
    const cert = certificates.find(c => c.id === id);
    if (!cert) {
        showAlert('错误', '证书不存在');
        return;
    }

    currentEditCertId = id;
    document.getElementById('certModalTitle').textContent = '编辑证书';
    document.getElementById('certEditName').value = cert.name;
    document.getElementById('certEditProvider').value = cert.provider || 'letsencrypt';
    document.getElementById('certEditCloudflareToken').value = cert.cloudflareApiToken || '';
    document.getElementById('certEditDomains').value = (cert.domains || '').replace(/,/g, '\n');
    document.getElementById('certEditAutoRenew').checked = cert.autoRenew === true || cert.autoRenew === 1;
    document.getElementById('certApplyForm').style.display = 'block';
    document.getElementById('certLogContainer').style.display = 'none';
    document.getElementById('certModalApplyBtn').disabled = false;
    document.getElementById('certModalApplyBtn').textContent = '保存';

    if (cert.provider === 'zerossl') {
        document.getElementById('certEditZeroSSLEmail').value = cert.acmeEmail || '';
        document.getElementById('zerosslFields').style.display = 'block';
        document.getElementById('letsencryptFields').style.display = 'none';
    } else {
        document.getElementById('certEditAcmeEmail').value = cert.acmeEmail || '';
        document.getElementById('zerosslFields').style.display = 'none';
        document.getElementById('letsencryptFields').style.display = 'block';
    }

    document.getElementById('certModal').classList.remove('modal-hidden');
}

async function stopCertificate(id) {
    showConfirm('确定要停止此证书的申请吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/certificates/${id}/stop`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', '证书申请已停止');
                loadCertificates();
            } else {
                showAlert('错误', data.error || '停止失败');
            }
        } catch (error) {
            console.error('停止证书失败:', error);
            showAlert('错误', error.message);
        }
    });
}

async function retryCertificate(id) {
    showConfirm('确定要重试此证书的申请吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/certificates/${id}/retry`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                loadCertificates();
            } else {
                showAlert('错误', data.error || '重试失败');
            }
        } catch (error) {
            console.error('重试证书失败:', error);
            showAlert('错误', error.message);
        }
    });
}

async function renewCertificate(id) {
    showConfirm('确定要续期此证书吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/certificates/${id}/renew`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', '证书续期请求已提交');
                await loadCertificates();
            } else {
                showAlert('错误', '证书续期失败: ' + data.error);
            }
        } catch (error) {
            console.error('证书续期失败:', error);
            showAlert('错误', '证书续期失败');
        }
    });
}

async function deleteCertificate(id) {
    showConfirm('确定要删除此证书吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/certificates/${id}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', '证书删除成功');
                await loadCertificates();
            } else {
                showAlert('错误', '删除失败');
            }
        } catch (error) {
            console.error('删除证书失败:', error);
            showAlert('错误', '删除失败');
        }
    });
}

async function loadPortForwardInstances() {
    try {
        const response = await fetch('/api/port-forward-instances');
        const result = await response.json();
        
        if (result.success && result.data) {
            portForwardInstances = result.data;
            renderPortForwardInstances();
        }
    } catch (error) {
        console.error('加载端口转发实例失败:', error);
    }
}

function renderPortForwardInstances() {
    const container = document.getElementById('portForwardInstancesList');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (portForwardInstances.length === 0) {
        container.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 200px; color: var(--text-muted);">暂无端口转发实例</div>';
        return;
    }
    
    portForwardInstances.forEach(instance => {
        const card = document.createElement('div');
        card.className = 'instance-item';
        
        const ipModeText = {
            'normal': '正常模式',
            'whitelist-only': '白名单模式',
            'blacklist-only': '黑名单模式'
        }[instance.ipMode] || instance.ipMode;
        
        const actionModeText = {
            'block': '拦截模式',
            'observe': '观察模式'
        }[instance.actionMode] || instance.actionMode;
        
        card.innerHTML = `
            <div class="instance-header">
                <div class="instance-name">
                    <span>🔀</span>
                    <span>${instance.name}</span>
                </div>
                <span class="instance-badge">端口: ${instance.listenPort}</span>
            </div>
            <div class="instance-grid">
                <div class="instance-grid-item">
                    <div class="instance-grid-label">协议</div>
                    <div class="instance-grid-value">${instance.protocol.toUpperCase()}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">目标地址</div>
                    <div class="instance-grid-value">${instance.targetAddress}:${instance.targetPort}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">IP 模式</div>
                    <div class="instance-grid-value">${ipModeText}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">动作模式</div>
                    <div class="instance-grid-value">${actionModeText}</div>
                </div>
                <div class="instance-grid-item">
                    <div class="instance-grid-label">创建时间</div>
                    <div class="instance-grid-value">${formatTime(instance.createdAt)}</div>
                </div>
            </div>
            <div class="instance-actions">
                <button class="btn-icon" onclick="editPortForwardInstance('${instance.id}')" title="编辑">✏️</button>
                <button class="btn-icon delete" onclick="deletePortForwardInstance('${instance.id}')" title="删除">🗑️</button>
            </div>
        `;
        
        container.appendChild(card);
    });
}

async function openCreatePortForwardModal() {
    currentEditPortForwardId = null;
    document.getElementById('portForwardModalTitle').textContent = '创建端口转发';
    document.getElementById('portForwardEditName').value = '';
    document.getElementById('portForwardEditProtocol').value = 'tcp';
    document.getElementById('portForwardEditListenPort').value = '';
    document.getElementById('portForwardEditTargetAddress').value = '';
    document.getElementById('portForwardEditTargetPort').value = '';
    document.getElementById('portForwardEditIPMode').value = 'normal';
    document.getElementById('portForwardEditActionMode').value = 'block';
    document.getElementById('portForwardModal').classList.remove('modal-hidden');
}

async function editPortForwardInstance(id) {
    const instance = portForwardInstances.find(p => p.id === id);
    if (!instance) {
        showAlert('错误', '端口转发实例不存在');
        return;
    }
    
    currentEditPortForwardId = id;
    document.getElementById('portForwardModalTitle').textContent = '编辑端口转发';
    document.getElementById('portForwardEditName').value = instance.name;
    document.getElementById('portForwardEditProtocol').value = instance.protocol;
    document.getElementById('portForwardEditListenPort').value = instance.listenPort;
    document.getElementById('portForwardEditTargetAddress').value = instance.targetAddress;
    document.getElementById('portForwardEditTargetPort').value = instance.targetPort;
    document.getElementById('portForwardEditIPMode').value = instance.ipMode;
    document.getElementById('portForwardEditActionMode').value = instance.actionMode;
    document.getElementById('portForwardModal').classList.remove('modal-hidden');
}

function closePortForwardModal() {
    document.getElementById('portForwardModal').classList.add('modal-hidden');
    currentEditPortForwardId = null;
}

async function savePortForwardEdit() {
    const name = document.getElementById('portForwardEditName').value;
    const protocol = document.getElementById('portForwardEditProtocol').value;
    const listenPort = parseInt(document.getElementById('portForwardEditListenPort').value);
    const targetAddress = document.getElementById('portForwardEditTargetAddress').value;
    const targetPort = parseInt(document.getElementById('portForwardEditTargetPort').value);
    const ipMode = document.getElementById('portForwardEditIPMode').value;
    const actionMode = document.getElementById('portForwardEditActionMode').value;
    
    if (!name || !listenPort || !targetAddress || !targetPort) {
        showAlert('提示', '请填写完整信息');
        return;
    }
    
    try {
        let response;
        if (currentEditPortForwardId) {
            response = await fetch(`/api/port-forward-instances/${currentEditPortForwardId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    protocol: protocol,
                    listenPort: listenPort,
                    targetAddress: targetAddress,
                    targetPort: targetPort,
                    ipMode: ipMode,
                    actionMode: actionMode
                })
            });
        } else {
            response = await fetch('/api/port-forward-instances', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: name,
                    protocol: protocol,
                    listenPort: listenPort,
                    targetAddress: targetAddress,
                    targetPort: targetPort,
                    ipMode: ipMode,
                    actionMode: actionMode
                })
            });
        }
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('成功', currentEditPortForwardId ? '更新成功' : '创建成功');
            closePortForwardModal();
            await loadPortForwardInstances();
        } else {
            showAlert('错误', (currentEditPortForwardId ? '更新' : '创建') + '失败: ' + data.error);
        }
    } catch (error) {
        console.error('保存端口转发失败:', error);
        showAlert('错误', (currentEditPortForwardId ? '更新' : '创建') + '失败');
    }
}

async function deletePortForwardInstance(id) {
    showConfirm('确定要删除此端口转发实例吗？', async (confirmed) => {
        if (!confirmed) return;
        
        try {
            const response = await fetch(`/api/port-forward-instances/${id}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert('成功', '删除成功');
                await loadPortForwardInstances();
            } else {
                showAlert('错误', '删除失败: ' + data.error);
            }
        } catch (error) {
            console.error('删除端口转发失败:', error);
            showAlert('错误', '删除失败');
        }
    });
}

async function loadLogs() {
    try {
        const filter = document.getElementById('logFilter').value;
        const searchKeyword = document.getElementById('logSearch').value;
        let url = `/api/logs?filter=${filter}&page=${currentLogsPage}&pageSize=${currentLogsPageSize}`;
        if (searchKeyword) {
            url += `&search=${encodeURIComponent(searchKeyword)}`;
        }
        const response = await fetch(url);
        const result = await response.json();
        
        const container = document.getElementById('logsContainer');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (result.success && result.data) {
            const logs = result.data;
            totalLogsPages = result.totalPages;
            
            if (logs.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.style.textAlign = 'center';
                cell.style.padding = '40px 20px';
                cell.style.color = 'var(--text-muted)';
                cell.textContent = '暂无数据';
                row.appendChild(cell);
                container.appendChild(row);
            } else {
                logs.forEach(log => {
                    const row = document.createElement('tr');
                    
                    const actionCell = document.createElement('td');
                    let bgColor = 'transparent';
                    let textColor = 'var(--text-primary)';
                    let actionText = '';
                    
                    if (log.action === 'detected') {
                        bgColor = '#F97316';
                        textColor = '#ffffff';
                        actionText = '未拦截';
                    } else if (log.action === 'blocked') {
                        bgColor = 'rgba(239, 68, 68,1)';
                        textColor = '#ffffff';
                        actionText = '已拦截';
                    } else if (log.action === 'normal') {
                        actionText = '已放行';
                        
                        if (log.filterType === 'whitelist_match' || log.filterType === 'blacklist_no_match' || log.filterType === 'whitelist_empty' || log.filterType === 'blacklist_empty' || log.filterType === 'normal') {
                            bgColor = 'rgba(34, 197, 94, 1)';
                            textColor = '#ffffff';
                        } else if (log.filterType === 'whitelist_no_match' || log.filterType === 'blacklist_match') {
                            bgColor = '#F97316';
                            textColor = '#ffffff';
                        } else {
                            bgColor = 'rgba(34, 197, 94, 1)';
                            textColor = '#ffffff';
                        }
                    }
                    const actionSpan = document.createElement('span');
                    actionSpan.textContent = actionText;
                    actionSpan.style.color = textColor;
                    actionSpan.style.backgroundColor = bgColor;
                    actionSpan.style.padding = '2px 8px';
                    actionSpan.style.borderRadius = '4px';
                    actionSpan.style.fontWeight = '600';
                    actionCell.appendChild(actionSpan);
                    row.appendChild(actionCell);
                    
                    const urlCell = document.createElement('td');
                    const urlLink = document.createElement('a');
                    urlLink.href = log.url;
                    urlLink.textContent = log.url;
                    urlLink.target = '_blank';
                    urlLink.rel = 'noopener noreferrer';
                    urlLink.style.maxWidth = '300px';
                    urlLink.style.overflow = 'hidden';
                    urlLink.style.textOverflow = 'ellipsis';
                    urlLink.style.whiteSpace = 'nowrap';
                    urlLink.style.display = 'inline-block';
                    urlLink.style.textDecoration = 'none';
                    urlLink.style.color = 'var(--text-primary)';
                    urlCell.appendChild(urlLink);
                    row.appendChild(urlCell);
                    
                    const attackTypeCell = document.createElement('td');
                    attackTypeCell.innerHTML = parseRules(log.rules);
                    row.appendChild(attackTypeCell);
                    
                    const ipCell = document.createElement('td');
                    ipCell.textContent = log.ip;
                    row.appendChild(ipCell);
                    
                    const locationCell = document.createElement('td');
                    const location = [];
                    if (log.country) location.push(log.country);
                    if (log.province) location.push(log.province);
                    if (log.city) location.push(log.city);
                    locationCell.textContent = location.length > 0 ? location.join(' ') : '-';
                    row.appendChild(locationCell);
                    
                    const timeCell = document.createElement('td');
                    timeCell.textContent = formatUTCTimeToLocal(log.time);
                    row.appendChild(timeCell);
                    
                    container.appendChild(row);
                });
            }
            
            updateLogsPagination(result.total, result.page, result.totalPages);
        }
    } catch (error) {
        console.error('加载日志失败:', error);
    }
}

function updateLogsPagination(total, page, totalPages) {
    const pageInfo = document.getElementById('logsPageInfo');
    const firstPageBtn = document.getElementById('logsFirstPage');
    const prevPageBtn = document.getElementById('logsPrevPage');
    const nextPageBtn = document.getElementById('logsNextPage');
    const lastPageBtn = document.getElementById('logsLastPage');
    
    if (pageInfo) {
        pageInfo.textContent = `第 ${page} 页 / 共 ${totalPages} 页 (共 ${total} 条)`;
    }
    
    if (firstPageBtn) {
        firstPageBtn.disabled = page <= 1;
    }
    
    if (prevPageBtn) {
        prevPageBtn.disabled = page <= 1;
    }
    
    if (nextPageBtn) {
        nextPageBtn.disabled = page >= totalPages;
    }
    
    if (lastPageBtn) {
        lastPageBtn.disabled = page >= totalPages;
    }
}

function goToLogsPage(page) {
    if (page < 1 || page > totalLogsPages) return;
    currentLogsPage = page;
    loadLogs();
}

function changeLogsPageSize() {
    const pageSizeSelect = document.getElementById('logsPageSize');
    if (pageSizeSelect) {
        currentLogsPageSize = parseInt(pageSizeSelect.value);
        currentLogsPage = 1;
        loadLogs();
    }
}

function resetLogsPage() {
    currentLogsPage = 1;
    loadLogs();
}

async function loadIPWhitelist() {
    try {
        console.log('开始加载IP白名单');
        const response = await fetch('/api/ip-whitelist');
        console.log('响应状态:', response.status, response.ok);
        
        if (!response.ok) {
            console.log('HTTP请求失败');
            const container = document.getElementById('ipWhitelistCount');
            if (container) {
                container.textContent = '暂无数据';
            }
            return;
        }
        
        const result = await response.json();
        console.log('响应数据:', result);
        
        const container = document.getElementById('ipWhitelistCount');
        if (!container) return;
        
        if (!result.success) {
            console.log('success为false');
            container.textContent = '暂无数据';
            return;
        }
        
        const data = result.data || [];
        const count = data.length;
        console.log('数据数量:', count);
        if (count === 0) {
            container.textContent = '暂无数据';
        } else {
            container.textContent = `共 ${count} 条记录`;
        }
    } catch (error) {
        console.error('加载IP白名单失败:', error);
        const container = document.getElementById('ipWhitelistCount');
        if (container) {
            container.textContent = '加载失败';
        }
    }
}

async function loadIPBlacklist() {
    try {
        console.log('开始加载IP黑名单');
        const response = await fetch('/api/ip-blacklist');
        console.log('响应状态:', response.status, response.ok);
        
        if (!response.ok) {
            console.log('HTTP请求失败');
            const container = document.getElementById('ipBlacklistCount');
            if (container) {
                container.textContent = '暂无数据';
            }
            return;
        }
        
        const result = await response.json();
        console.log('响应数据:', result);
        
        const container = document.getElementById('ipBlacklistCount');
        if (!container) return;
        
        if (!result.success) {
            console.log('success为false');
            container.textContent = '暂无数据';
            return;
        }
        
        const data = result.data || [];
        const count = data.length;
        console.log('数据数量:', count);
        if (count === 0) {
            container.textContent = '暂无数据';
        } else {
            container.textContent = `共 ${count} 条记录`;
        }
    } catch (error) {
        console.error('加载IP黑名单失败:', error);
        const container = document.getElementById('ipBlacklistCount');
        if (container) {
            container.textContent = '加载失败';
        }
    }
}

async function openAddIPWhitelistModal() {
    try {
        const response = await fetch('/api/ip-whitelist');
        const result = await response.json();
        
        const textarea = document.getElementById('whitelistIPs');
        if (result.success && result.data.length > 0) {
            const ips = result.data.map(entry => entry.ip).join('\n');
            textarea.value = ips;
        } else {
            textarea.value = '';
        }
        
        document.getElementById('ipWhitelistModal').classList.remove('modal-hidden');
    } catch (error) {
        console.error('加载白名单失败:', error);
        document.getElementById('whitelistIPs').value = '';
        document.getElementById('ipWhitelistModal').classList.remove('modal-hidden');
    }
}

async function openAddIPBlacklistModal() {
    try {
        const response = await fetch('/api/ip-blacklist');
        const result = await response.json();
        
        const textarea = document.getElementById('blacklistIPs');
        if (result.success && result.data.length > 0) {
            const ips = result.data.map(entry => entry.ip).join('\n');
            textarea.value = ips;
        } else {
            textarea.value = '';
        }
        
        document.getElementById('ipBlacklistModal').classList.remove('modal-hidden');
    } catch (error) {
        console.error('加载黑名单失败:', error);
        document.getElementById('blacklistIPs').value = '';
        document.getElementById('ipBlacklistModal').classList.remove('modal-hidden');
    }
}

function closeIPWhitelistModal() {
    document.getElementById('ipWhitelistModal').classList.add('modal-hidden');
}

function closeIPBlacklistModal() {
    document.getElementById('ipBlacklistModal').classList.add('modal-hidden');
}

function openRIRImportModal() {
    document.getElementById('rirImportModal').classList.remove('modal-hidden');
}

function closeRIRImportModal() {
    document.getElementById('rirImportModal').classList.add('modal-hidden');
}

async function startRIRImport() {
    const urlInput = document.getElementById('rirImportUrl');
    const rulesInput = document.getElementById('rirImportRules');
    const listTypeInputs = document.getElementsByName('rirListType');
    let listType = 'whitelist';
    
    for (const input of listTypeInputs) {
        if (input.checked) {
            listType = input.value;
            break;
        }
    }
    
    const rirUrl = urlInput.value.trim();
    const rulesText = rulesInput.value.trim();
    
    if (!rirUrl) {
        showAlert('错误', '请输入RIR接口地址');
        return;
    }
    
    const rules = rulesText.split('\n').map(rule => rule.trim()).filter(rule => rule !== '');
    
    if (rules.length === 0) {
        showAlert('错误', '请输入至少一个IP过滤规则');
        return;
    }
    
    const button = document.getElementById('rirImportButton');
    const logDiv = document.getElementById('rirImportLog');
    
    button.disabled = true;
    button.textContent = '导入中...';
    logDiv.innerHTML = '开始导入...<br>';
    
    let progressInterval = null;
    
    try {
        const response = await fetch('/api/rir-import', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                rir_url: rirUrl,
                rules: rules,
                list_type: listType
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            logDiv.innerHTML += `${result.message || '导入任务已启动'}<br>`;
            
            progressInterval = setInterval(async () => {
                try {
                    const progressResponse = await fetch('/api/rir-import-progress');
                    const progress = await progressResponse.json();
                    
                    if (progress.message) {
                        logDiv.innerHTML += `${progress.message}<br>`;
                        logDiv.scrollTop = logDiv.scrollHeight;
                    }
                    
                    if (progress.status === 'completed') {
                        clearInterval(progressInterval);
                        button.disabled = false;
                        button.textContent = '📥 开始导入';
                        
                        await loadIPWhitelist();
                        await loadIPBlacklist();
                        
                        showAlert('成功', 'RIR导入完成');
                    } else if (progress.status === 'error') {
                        clearInterval(progressInterval);
                        button.disabled = false;
                        button.textContent = '📥 开始导入';
                        
                        logDiv.innerHTML += `<span style="color: rgba(239, 68, 68, 1);">${progress.message || '导入失败'}</span><br>`;
                        showAlert('错误', progress.message || '导入失败');
                    }
                } catch (error) {
                    console.error('获取导入进度失败:', error);
                }
            }, 1000);
        } else {
            logDiv.innerHTML += `<span style="color: rgba(239, 68, 68, 1);">${result.error || '导入失败'}</span><br>`;
            showAlert('错误', result.error || '导入失败');
            button.disabled = false;
            button.textContent = '📥 开始导入';
        }
    } catch (error) {
        console.error('导入RIR数据失败:', error);
        logDiv.innerHTML += `<span style="color: rgba(239, 68, 68, 1);">导入失败: ${error.message}</span><br>`;
        showAlert('错误', '导入失败，请检查网络连接');
        button.disabled = false;
        button.textContent = '📥 开始导入';
        if (progressInterval) {
            clearInterval(progressInterval);
        }
    }
}

async function saveIPWhitelist() {
    const textarea = document.getElementById('whitelistIPs');
    const ips = textarea.value.trim().split('\n').map(ip => ip.trim()).filter(ip => ip !== '');
    
    if (ips.length > 0) {
        const invalidIPs = [];
        for (const ip of ips) {
            if (!validateIPFormat(ip)) {
                invalidIPs.push(ip);
            }
        }
        
        if (invalidIPs.length > 0) {
            showAlert('错误', `以下IP地址格式不正确：\n${invalidIPs.join('\n')}`);
            return;
        }
    }
    
    try {
        const response = await fetch('/api/ip-whitelist/batch', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ips: ips
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('成功', '保存成功');
            closeIPWhitelistModal();
            loadIPWhitelist();
        } else {
            showAlert('错误', data.error || '保存失败');
        }
    } catch (error) {
        console.error('保存IP白名单失败:', error);
        showAlert('错误', '保存失败');
    }
}

async function saveIPBlacklist() {
    const textarea = document.getElementById('blacklistIPs');
    const ips = textarea.value.trim().split('\n').map(ip => ip.trim()).filter(ip => ip !== '');
    
    if (ips.length > 0) {
        const invalidIPs = [];
        for (const ip of ips) {
            if (!validateIPFormat(ip)) {
                invalidIPs.push(ip);
            }
        }
        
        if (invalidIPs.length > 0) {
            showAlert('错误', `以下IP地址格式不正确：\n${invalidIPs.join('\n')}`);
            return;
        }
    }
    
    try {
        const response = await fetch('/api/ip-blacklist/batch', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ips: ips
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('成功', '保存成功');
            closeIPBlacklistModal();
            loadIPBlacklist();
        } else {
            showAlert('错误', data.error || '保存失败');
        }
    } catch (error) {
        console.error('保存IP黑名单失败:', error);
        showAlert('错误', '保存失败');
    }
}

async function loadIPMode() {
    try {
        const response = await fetch('/api/ip-settings');
        const result = await response.json();
        
        if (result.success) {
            const mode = result.mode || 'normal';
            const actionMode = result.action_mode || 'block';
            
            const modeRadio = document.querySelector(`input[name="ipMode"][value="${mode}"]`);
            if (modeRadio) {
                modeRadio.checked = true;
            }
            
            const actionModeRadio = document.querySelector(`input[name="actionMode"][value="${actionMode}"]`);
            if (actionModeRadio) {
                actionModeRadio.checked = true;
            }
        }
    } catch (error) {
        console.error('加载IP模式失败:', error);
    }
}

async function saveIPMode() {
    const selectedMode = document.querySelector('input[name="ipMode"]:checked');
    const selectedActionMode = document.querySelector('input[name="actionMode"]:checked');
    
    if (!selectedMode || !selectedActionMode) {
        console.error('未选择模式');
        return;
    }
    
    const mode = selectedMode.value;
    const actionMode = selectedActionMode.value;
    console.log('保存IP模式:', mode, actionMode);
    
    try {
        const response = await fetch('/api/ip-settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                mode: mode,
                action_mode: actionMode
            })
        });
        
        console.log('响应状态:', response.status);
        const data = await response.json();
        console.log('响应数据:', data);
        
        if (data.success) {
            showAlert('成功', '模式已切换');
        } else {
            showAlert('错误', data.error || '切换模式失败');
        }
    } catch (error) {
        console.error('保存IP模式失败:', error);
        showAlert('错误', '切换模式失败');
    }
}

function validateIPFormat(ip) {
    const ipv4SingleRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv4CIDRRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    
    if (ipv4SingleRegex.test(ip)) {
        const parts = ip.split('.');
        for (let i = 0; i < 4; i++) {
            const num = parseInt(parts[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }
        return true;
    }
    
    if (ipv4CIDRRegex.test(ip)) {
        const parts = ip.split('/');
        const ipParts = parts[0].split('.');
        for (let i = 0; i < 4; i++) {
            const num = parseInt(ipParts[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }
        const mask = parseInt(parts[1]);
        if (mask < 0 || mask > 32) {
            return false;
        }
        return true;
    }
    
    const parts = ip.split('/');
    const address = parts[0];
    
    if (parts.length > 2) {
        return false;
    }
    
    const ipv6Regex = /^[0-9a-fA-F:]+$/;
    if (!ipv6Regex.test(address)) {
        return false;
    }
    
    const hasDoubleColon = address.includes('::');
    const colons = (address.match(/:/g) || []).length;
    
    if (hasDoubleColon) {
        if (address.indexOf('::') !== address.lastIndexOf('::')) {
            return false;
        }
        if (colons < 2 || colons > 7) {
            return false;
        }
    } else {
        if (colons !== 7) {
            return false;
        }
    }
    
    const segments = address.split(':');
    for (const seg of segments) {
        if (seg === '') continue;
        if (seg.length > 4) {
            return false;
        }
        if (!/^[0-9a-fA-F]{1,4}$/.test(seg)) {
            return false;
        }
    }
    
    if (parts.length === 2) {
        const mask = parseInt(parts[1]);
        if (isNaN(mask) || mask < 0 || mask > 128) {
            return false;
        }
    }
    
    return true;
}

let ipAccessLogsCurrentPage = 1;
let ipAccessLogsPageSize = 20;
let ipAccessLogsTotalPages = 1;

async function loadIPAccessLogs() {
    try {
        const modeFilter = document.getElementById('ipLogModeFilter').value;
        const resultFilter = document.getElementById('ipLogResultFilter').value;
        const searchKeyword = document.getElementById('ipLogSearch').value;
        
        let url = `/api/ip-access-logs?page=${ipAccessLogsCurrentPage}&pageSize=${ipAccessLogsPageSize}`;
        if (modeFilter) {
            url += `&mode=${modeFilter}`;
        }
        if (resultFilter) {
            url += `&result=${resultFilter}`;
        }
        if (searchKeyword) {
            url += `&search=${encodeURIComponent(searchKeyword)}`;
        }
        
        const response = await fetch(url);
        const result = await response.json();
        
        const container = document.getElementById('ipAccessLogsContainer');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!result.success || result.data.length === 0) {
            container.innerHTML = '<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">暂无数据</td></tr>';
            ipAccessLogsTotalPages = 0;
            updateIPAccessLogsPagination(0, 1, 20);
            return;
        }
        
        result.data.forEach(log => {
            const row = document.createElement('tr');
            
            const modeText = {
                'normal': '正常模式',
                'whitelist-only': '白名单模式',
                'blacklist-only': '黑名单模式'
            }[log.mode] || log.mode;
            
            const actionText = {
                'whitelist_match': '白名单匹配',
                'whitelist_no_match': '白名单不匹配',
                'whitelist_empty': '白名单为空',
                'blacklist_match': '黑名单匹配',
                'blacklist_no_match': '黑名单不匹配',
                'blacklist_empty': '黑名单为空',
                'normal': '正常'
            }[log.action] || log.action;
            
            const resultText = log.result === 'pass' ? '通过' : (log.result === 'observe' ? '观察' : '拦截');
            const resultColor = log.result === 'pass' ? 'rgba(34, 197, 94, 1)' : (log.result === 'observe' ? 'rgba(249, 115, 22, 1)' : 'rgba(239, 68, 68, 1)');

            const forwardTypeText = {
                'reverse_proxy': '反代',
                'port_forward': '端口转发'
            }[log.forward_type] || log.forward_type || '-';

            const location = [];
            if (log.country) location.push(log.country);
            if (log.province) location.push(log.province);
            if (log.city) location.push(log.city);
            const locationText = location.length > 0 ? location.join(' ') : '-';

            const urlLink = log.url ? `<a href="${log.url}" target="_blank" rel="noopener noreferrer" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; text-decoration: none; color: var(--text-primary);">${log.url}</a>` : '-';
            
            row.innerHTML = `
                <td><span style="background-color: ${resultColor}; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 13px;">${resultText}</span></td>
                <td>${actionText}</td>
                <td>${urlLink}</td>
                <td>${log.ip}</td>
                <td>${locationText}</td>
                <td>${modeText}</td>
                <td>${forwardTypeText}</td>
                <td>${log.instance_name || '-'}</td>
                <td style="font-family: monospace; font-size: 12px;">${log.forward_info || '-'}</td>
                <td>${formatUTCTimeToLocal(log.created_at)}</td>
            `;
            
            container.appendChild(row);
        });
        
        ipAccessLogsTotalPages = Math.ceil(result.total / result.pageSize);
        updateIPAccessLogsPagination(result.total, result.page, result.pageSize);
    } catch (error) {
        console.error('加载IP访问日志失败:', error);
        const container = document.getElementById('ipAccessLogsContainer');
        if (container) {
            container.innerHTML = '<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">加载失败</td></tr>';
        }
    }
}

function updateIPAccessLogsPagination(total, page, pageSize) {
    const totalPages = Math.ceil(total / pageSize);
    const pageInfo = document.getElementById('ipAccessLogsPageInfo');
    const firstPageBtn = document.getElementById('ipAccessLogsFirstPage');
    const prevPageBtn = document.getElementById('ipAccessLogsPrevPage');
    const nextPageBtn = document.getElementById('ipAccessLogsNextPage');
    const lastPageBtn = document.getElementById('ipAccessLogsLastPage');
    
    if (pageInfo) {
        pageInfo.textContent = `第 ${page} 页 / 共 ${totalPages} 页 (共 ${total} 条)`;
    }
    
    if (firstPageBtn) {
        firstPageBtn.disabled = page <= 1;
    }
    
    if (prevPageBtn) {
        prevPageBtn.disabled = page <= 1;
    }
    
    if (nextPageBtn) {
        nextPageBtn.disabled = page >= totalPages;
    }
    
    if (lastPageBtn) {
        lastPageBtn.disabled = page >= totalPages;
    }
}

function goToIPAccessLogsPage(page) {
    if (page < 1 || page > ipAccessLogsTotalPages) return;
    ipAccessLogsCurrentPage = page;
    loadIPAccessLogs();
}

function changeIPAccessLogsPageSize() {
    const pageSizeSelect = document.getElementById('ipAccessLogsPageSize');
    if (pageSizeSelect) {
        ipAccessLogsPageSize = parseInt(pageSizeSelect.value);
        ipAccessLogsCurrentPage = 1;
        loadIPAccessLogs();
    }
}

function resetIPAccessLogsPage() {
    ipAccessLogsCurrentPage = 1;
    loadIPAccessLogs();
}

async function clearIPAccessLogs() {
    showConfirm('确定要清空所有IP访问日志吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch('/api/ip-access-logs', {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', '日志已清空');
                ipAccessLogsCurrentPage = 1;
                loadIPAccessLogs();
            } else {
                showAlert('错误', '清空日志失败: ' + data.error);
            }
        } catch (error) {
            console.error('清空日志失败:', error);
            showAlert('错误', '清空日志失败');
        }
    });
}

async function deleteIPAccessSearchResults() {
    const searchKeyword = document.getElementById('ipLogSearch').value;
    if (!searchKeyword) {
        showAlert('提示', '请输入搜索关键字');
        return;
    }

    showConfirm(`确定要删除包含"${searchKeyword}"的所有IP访问日志吗？`, async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/ip-access-logs?search=${encodeURIComponent(searchKeyword)}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', `已删除 ${data.deleted || 0} 条日志`);
                document.getElementById('ipLogSearch').value = '';
                ipAccessLogsCurrentPage = 1;
                loadIPAccessLogs();
            } else {
                showAlert('错误', '删除日志失败: ' + data.error);
            }
        } catch (error) {
            console.error('删除日志失败:', error);
            showAlert('错误', '删除日志失败');
        }
    });
}

function parseRules(rulesStr) {
    if (!rulesStr || rulesStr === '无') {
        return '无';
    }
    
    try {
        const rules = JSON.parse('[' + rulesStr + ']');
        return rules.map(rule => {
            return rule.message;
        }).join('<br>');
    } catch (e) {
        return rulesStr;
    }
}

async function clearLogs() {
    showConfirm('确定要清空所有日志吗？', async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch('/api/logs', {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', '日志已清空');
                loadLogs();
            } else {
                showAlert('错误', '清空日志失败: ' + data.error);
            }
        } catch (error) {
            console.error('清空日志失败:', error);
            showAlert('错误', '清空日志失败');
        }
    });
}

async function deleteSearchResults() {
    const searchKeyword = document.getElementById('logSearch').value;
    if (!searchKeyword) {
        showAlert('提示', '请输入搜索关键字');
        return;
    }

    showConfirm(`确定要删除包含"${searchKeyword}"的所有日志吗？`, async (confirmed) => {
        if (!confirmed) return;

        try {
            const response = await fetch(`/api/logs?search=${encodeURIComponent(searchKeyword)}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('成功', `已删除 ${data.deleted || 0} 条日志`);
                document.getElementById('logSearch').value = '';
                loadLogs();
            } else {
                showAlert('错误', '删除日志失败: ' + data.error);
            }
        } catch (error) {
            console.error('删除日志失败:', error);
            showAlert('错误', '删除日志失败');
        }
    });
}

async function logout() {
    if (isLoggedIn) {
        try {
            await fetch('/api/logout');
            isLoggedIn = false;
            window.location.reload();
        } catch (error) {
            console.error('登出失败:', error);
        }
    } else {
        window.location.href = '/login.html';
    }
}

async function loadStats() {
    try {
        const [statsResponse, historyResponse, clientStatsResponse] = await Promise.all([
            fetch('/api/statistics'),
            fetch('/api/statistics/history'),
            fetch('/api/client-stats')
        ]);
        
        const stats = await statsResponse.json();
        const history = await historyResponse.json();
        const clientStats = await clientStatsResponse.json();
        
        statsData = stats;
        historyData = history;
        top5ClientStats = clientStats;
        fullClientStats = null;
        
        console.log('statsData:', statsData);
        console.log('accessGeoDistribution:', statsData.accessGeoDistribution);
        console.log('accessProvinceDistribution:', statsData.accessProvinceDistribution);
        console.log('detectedGeoDistribution:', statsData.detectedGeoDistribution);
        console.log('detectedProvinceDistribution:', statsData.detectedProvinceDistribution);
        console.log('blockedGeoDistribution:', statsData.blockedGeoDistribution);
        console.log('blockedProvinceDistribution:', statsData.blockedProvinceDistribution);
        
        document.getElementById('statRequestCount').textContent = formatNumber(statsData.requestCount);
        document.getElementById('statPV').textContent = formatNumber(statsData.pv);
        document.getElementById('statUV').textContent = formatNumber(statsData.uv);
        document.getElementById('statUniqueIP').textContent = formatNumber(statsData.uniqueIP);
        
        document.getElementById('statRequestCount-mobile')?.setAttribute('data-value', statsData.requestCount);
        document.getElementById('statPV-mobile')?.setAttribute('data-value', statsData.pv);
        document.getElementById('statUV-mobile')?.setAttribute('data-value', statsData.uv);
        document.getElementById('statUniqueIP-mobile')?.setAttribute('data-value', statsData.uniqueIP);
        if (document.getElementById('statRequestCount-mobile')) document.getElementById('statRequestCount-mobile').textContent = formatNumber(statsData.requestCount);
        if (document.getElementById('statPV-mobile')) document.getElementById('statPV-mobile').textContent = formatNumber(statsData.pv);
        if (document.getElementById('statUV-mobile')) document.getElementById('statUV-mobile').textContent = formatNumber(statsData.uv);
        if (document.getElementById('statUniqueIP-mobile')) document.getElementById('statUniqueIP-mobile').textContent = formatNumber(statsData.uniqueIP);
        
        document.getElementById('statBlockedCount').textContent = formatNumber(statsData.blockedCount);
        document.getElementById('statAttackIP').textContent = formatNumber(statsData.attackIP);
        document.getElementById('stat4xxBlocked').textContent = formatNumber(statsData.blockedCount);
        document.getElementById('stat4xxBlockRate').textContent = statsData.fourXxBlockRate ? statsData.fourXxBlockRate.toFixed(2) + '%' : '0%';
        
        if (document.getElementById('statBlockedCount-mobile')) document.getElementById('statBlockedCount-mobile').textContent = formatNumber(statsData.blockedCount);
        if (document.getElementById('statAttackIP-mobile')) document.getElementById('statAttackIP-mobile').textContent = formatNumber(statsData.attackIP);
        if (document.getElementById('stat4xxBlocked-mobile')) document.getElementById('stat4xxBlocked-mobile').textContent = formatNumber(statsData.blockedCount);
        if (document.getElementById('stat4xxBlockRate-mobile')) document.getElementById('stat4xxBlockRate-mobile').textContent = statsData.fourXxBlockRate ? statsData.fourXxBlockRate.toFixed(2) + '%' : '0%';
        
        document.getElementById('stat4xxError').textContent = formatNumber(statsData.fourXxError);
        document.getElementById('stat4xxErrorRate').textContent = statsData.fourXxErrorRate ? statsData.fourXxErrorRate.toFixed(2) + '%' : '0%';
        document.getElementById('stat5xxError').textContent = formatNumber(statsData.fiveXxError);
        document.getElementById('stat5xxErrorRate').textContent = statsData.fiveXxErrorRate ? statsData.fiveXxErrorRate.toFixed(2) + '%' : '0%';
        
        if (document.getElementById('stat4xxError-mobile')) document.getElementById('stat4xxError-mobile').textContent = formatNumber(statsData.fourXxError);
        if (document.getElementById('stat4xxErrorRate-mobile')) document.getElementById('stat4xxErrorRate-mobile').textContent = statsData.fourXxErrorRate ? statsData.fourXxErrorRate.toFixed(2) + '%' : '0%';
        if (document.getElementById('stat5xxError-mobile')) document.getElementById('stat5xxError-mobile').textContent = formatNumber(statsData.fiveXxError);
        if (document.getElementById('stat5xxErrorRate-mobile')) document.getElementById('stat5xxErrorRate-mobile').textContent = statsData.fiveXxErrorRate ? statsData.fiveXxErrorRate.toFixed(2) + '%' : '0%';
        
        document.getElementById('statAvgResponseTime').textContent = statsData.avgResponseTime > 0 ? statsData.avgResponseTime + 'ms' : '-';
        if (document.getElementById('statAvgResponseTime-mobile')) document.getElementById('statAvgResponseTime-mobile').textContent = statsData.avgResponseTime > 0 ? statsData.avgResponseTime + 'ms' : '-';
        const qpsBadgeValue = document.getElementById('qps-badge-value');
        if (qpsBadgeValue) {
            qpsBadgeValue.textContent = statsData.qps;
        }
        const qpsBadgeValueMobile = document.getElementById('qps-badge-value-mobile');
        if (qpsBadgeValueMobile) {
            qpsBadgeValueMobile.textContent = statsData.qps;
        }
        
        const attackBadgeValue = document.getElementById('attack-badge-value');
        if (attackBadgeValue) {
            const attackHistory = historyData.attackHistory || [];
            const currentAttack = attackHistory.length > 0 ? attackHistory[attackHistory.length - 1].count : 0;
            attackBadgeValue.textContent = currentAttack;
        }
        const attackBadgeValueMobile = document.getElementById('attack-badge-value-mobile');
        if (attackBadgeValueMobile) {
            const attackHistory = historyData.attackHistory || [];
            const currentAttack = attackHistory.length > 0 ? attackHistory[attackHistory.length - 1].count : 0;
            attackBadgeValueMobile.textContent = currentAttack;
        }
        
        document.getElementById('statPVPeak').textContent = formatNumber(statsData.pvPeak);
        document.getElementById('statBlockPeak').textContent = formatNumber(statsData.blockPeak);
        document.getElementById('statWAFCount').textContent = wafInstances.length;
        if (document.getElementById('statPVPeak-mobile')) document.getElementById('statPVPeak-mobile').textContent = formatNumber(statsData.pvPeak);
        if (document.getElementById('statBlockPeak-mobile')) document.getElementById('statBlockPeak-mobile').textContent = formatNumber(statsData.blockPeak);
        if (document.getElementById('statWAFCount-mobile')) document.getElementById('statWAFCount-mobile').textContent = wafInstances.length;
        
        renderGeoDistribution();
        renderGeoDistributionMobile();
        renderGeoMapMobile();
        
        const recentAttacksContainer = document.getElementById('recentAttacks');
        if (recentAttacksContainer) {
            const logsResponse = await fetch('/api/logs?filter=attack');
            const logsResult = await logsResponse.json();
            const attackLogs = logsResult.data || logsResult || [];
            
            const ipAccessLogsResponse = await fetch('/api/ip-access-logs?result=observe&pageSize=5');
            const ipAccessLogsResult = await ipAccessLogsResponse.json();
            const ipAccessLogsObserve = ipAccessLogsResult.data || ipAccessLogsResult || [];
            
            const ipAccessLogsBlockResponse = await fetch('/api/ip-access-logs?result=block&pageSize=5');
            const ipAccessLogsBlockResult = await ipAccessLogsBlockResponse.json();
            const ipAccessLogsBlock = ipAccessLogsBlockResult.data || ipAccessLogsBlockResult || [];
            
            const allLogs = [...attackLogs, ...ipAccessLogsObserve, ...ipAccessLogsBlock].sort((a, b) => {
                const timeA = a.time || a.created_at || '';
                const timeB = b.time || b.created_at || '';
                return timeB.localeCompare(timeA);
            });
            
            const recentAttacks = Array.isArray(allLogs) ? allLogs.slice(0, 5) : [];

            recentAttacksContainer.innerHTML = recentAttacks.map(log => {
                let statusText = '未拦截';
                let statusColor = 'var(--text-secondary)';
                let barColor = 'rgba(0, 0, 0, 0.03)';
                
                if (log.action === 'detected' || log.result === 'observe') {
                    statusText = '观察';
                    statusColor = '#f59e0b';
                    barColor = 'rgba(245, 158, 11, 0.08)';
                } else if (log.action === 'blocked' || log.result === 'block') {
                    statusText = '拦截';
                    statusColor = '#ef4444';
                    barColor = 'rgba(239, 68, 68, 0.08)';
                }
                
                const url = log.url || (log.forward_info ? log.forward_info : '未知地址');
                
                return `
                <div class="rank-list-row">
                    <div class="rank-list-bar" style="width: 100%; background: ${barColor};"></div>
                    <span class="rank-list-name" title="${url}">${url}</span>
                    <span class="rank-list-value" style="color: ${statusColor};">${statusText}</span>
                </div>
                `;
            }).join('');
        }
        
        const attackIPRankingsContainer = document.getElementById('attackIPRankings');
        if (attackIPRankingsContainer) {
            const reportResponse = await fetch('/api/ip-access-logs/report');
            const reportResult = await reportResponse.json();
            const topAttackIPs = (reportResult.data && reportResult.data.topAttackIPs) || [];

            if (topAttackIPs.length === 0) {
                attackIPRankingsContainer.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 100%; color: var(--text-muted);">暂无数据</div>';
            } else {
                const maxCount = Math.max(...topAttackIPs.map(ip => ip.count), 1);
                attackIPRankingsContainer.innerHTML = topAttackIPs.slice(0, 5).map((ip, index) => {
                    const rankColor = index < 3 ? '#ef4444' : 'var(--text-secondary)';
                    const percentage = (ip.count / maxCount) * 100;
                    return `
                    <div class="rank-list-row">
                        <div class="rank-list-bar" style="width: ${percentage}%;"></div>
                        <span class="rank-list-name" style="font-family: monospace;">${ip.ip}</span>
                        <span class="rank-list-value" style="color: ${rankColor}; font-weight: 600;">${ip.count}</span>
                    </div>
                    `;
                }).join('');
            }

            const attackIPRankingsMobileContainer = document.getElementById('attackIPRankings-mobile');
            if (attackIPRankingsMobileContainer) {
                if (topAttackIPs.length === 0) {
                    attackIPRankingsMobileContainer.innerHTML = '<div style="display: flex; justify-content: center; align-items: center; height: 80px; color: var(--text-muted); font-size: 12px;">暂无数据</div>';
                } else {
                    const maxCount = Math.max(...topAttackIPs.map(ip => ip.count), 1);
                    attackIPRankingsMobileContainer.innerHTML = topAttackIPs.slice(0, 5).map((ip, index) => {
                        const rankColor = index < 3 ? '#ef4444' : 'var(--text-secondary)';
                        const percentage = (ip.count / maxCount) * 100;
                        return `
                        <div class="rank-list-item">
                            <div class="rank-list-bar" style="width: ${percentage}%;"></div>
                            <span class="rank-list-name" style="font-family: monospace; font-size: 11px;">${ip.ip}</span>
                            <span class="rank-list-value" style="color: ${rankColor}; font-weight: 600; font-size: 11px;">${ip.count}</span>
                        </div>
                        `;
                    }).join('');
                }
            }
        }
        
        const recentAttacksMobileContainer = document.getElementById('recentAttacks-mobile');
        if (recentAttacksMobileContainer && recentAttacksContainer) {
            recentAttacksMobileContainer.innerHTML = recentAttacksContainer.innerHTML;
        }
        
        renderQPSChart();
        renderQPSChartMobile();
        renderTrafficChart();
        renderTrafficChartMobile();
        renderAttackChart();
        renderAttackChartMobile();
        renderTrendChart();
        renderTrendChartMobile();
        
        // 渲染客户端统计
        if (top5ClientStats.success) {
            const clientStatsContainer = document.getElementById('clientStatsContainer');
            
            if (clientStatsContainer) {
                const platforms = top5ClientStats.platforms || [];
                const browsers = top5ClientStats.browsers || [];
                const maxItems = Math.max(platforms.length, browsers.length);
                const rankColors = ['#FF6B6B', '#FFA726', '#FFD93D', '#6BCB77', '#4D96FF'];
                
                let html = `
                <div style="display: flex; gap: 20px; align-items: center; width: 100%; height: 100%;">
                    <div style="width: 150px; display: flex; justify-content: center;">
                        <canvas id="clientDonutChart" width="140" height="140"></canvas>
                    </div>
                    <div style="flex: 1; display: flex; gap: 15px;">
                        <div style="flex: 1;">
                `;
                
                // 渲染平台列
                for (let i = 0; i < maxItems; i++) {
                    if (platforms[i]) {
                        const p = platforms[i];
                        const rankColor = i < rankColors.length ? rankColors[i] : '#4D96FF';
                        html += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 0;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <div style="width: 8px; height: 8px; border-radius: 50%; background: ${rankColor};"></div>
                                <span style="color: var(--text-primary); font-size: 14px;">${p.name}</span>
                            </div>
                            <span style="color: #000; font-weight: 600; font-size: 14px;">${formatNumber(p.count)}</span>
                        </div>
                        `;
                    } else {
                        html += `<div style="padding: 6px 0;"></div>`;
                    }
                }
                
                html += `
                        </div>
                        <div style="flex: 1;">
                `;
                
                // 渲染浏览器列
                for (let i = 0; i < maxItems; i++) {
                    if (browsers[i]) {
                        const b = browsers[i];
                        const rankColor = i < rankColors.length ? rankColors[i] : '#4D96FF';
                        html += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 0;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <div style="width: 8px; height: 8px; border-radius: 50%; background: ${rankColor};"></div>
                                <span style="color: var(--text-primary); font-size: 14px;">${b.name}</span>
                            </div>
                            <span style="color: #000; font-weight: 600; font-size: 14px;">${formatNumber(b.count)}</span>
                        </div>
                        `;
                    } else {
                        html += `<div style="padding: 6px 0;"></div>`;
                    }
                }
                
                html += `
                        </div>
                    </div>
                </div>
                `;
                
                clientStatsContainer.innerHTML = html;
                
                // 绘制同心圆饼图
                drawNestedDonutChart('clientDonutChart', platforms, browsers, rankColors);
            }
        }
        
        // 手机端客户端统计渲染
        const clientStatsContainerMobile = document.getElementById('clientStatsContainer-mobile');
        if (clientStatsContainerMobile && top5ClientStats.success) {
            const platforms = top5ClientStats.platforms || [];
            const browsers = top5ClientStats.browsers || [];
            const maxItems = Math.max(platforms.length, browsers.length);
            const rankColors = ['#FF6B6B', '#FFA726', '#FFD93D', '#6BCB77', '#4D96FF'];
            
            let html = `
                <div style="display: flex; justify-content: center; padding: 10px 0;">
                    <canvas id="clientDonutChart-mobile" width="160" height="160"></canvas>
                </div>
                <div style="display: flex; gap: 15px; padding: 10px; font-size: 12px;">
                    <div style="flex: 1;">
            `;
            
            for (let i = 0; i < maxItems; i++) {
                if (platforms[i]) {
                    const p = platforms[i];
                    html += `
                    <div style="display: flex; justify-content: space-between; padding: 4px 0;">
                        <div style="display: flex; align-items: center; gap: 5px;">
                            <div style="width: 8px; height: 8px; border-radius: 50%; background: ${rankColors[i]};"></div>
                            <span>${p.name}</span>
                        </div>
                        <span style="font-weight: 600;">${formatNumber(p.count)}</span>
                    </div>
                    `;
                }
            }
            
            html += `
                    </div>
                    <div style="flex: 1;">
            `;
            
            for (let i = 0; i < maxItems; i++) {
                if (browsers[i]) {
                    const b = browsers[i];
                    html += `
                    <div style="display: flex; justify-content: space-between; padding: 4px 0;">
                        <div style="display: flex; align-items: center; gap: 5px;">
                            <div style="width: 8px; height: 8px; border-radius: 50%; background: ${rankColors[i]};"></div>
                            <span>${b.name}</span>
                        </div>
                        <span style="font-weight: 600;">${formatNumber(b.count)}</span>
                    </div>
                    `;
                }
            }
            
            html += `
                    </div>
                </div>
            `;
            
            clientStatsContainerMobile.innerHTML = html;
            
            // 绘制手机端饼图
            drawNestedDonutChart('clientDonutChart-mobile', platforms, browsers, rankColors);
        }
        
        console.log('图表渲染完成');
        console.log('QPS历史数据:', historyData.qpsHistory);
        console.log('流量历史数据:', historyData.trafficHistory);
        console.log('攻击历史数据:', historyData.attackHistory);
    } catch (error) {
        console.error('加载统计数据失败:', error);
    }
}

function drawNestedDonutChart(canvasId, platformData, browserData, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const scale = centerX / 70;
    
    const rankColors = colors || ['#FF6B6B', '#FFA726', '#FFD93D', '#6BCB77', '#4D96FF'];
    
    const outerOuterRadius = 60 * scale;
    const outerInnerRadius = 43 * scale;
    const innerOuterRadius = 30 * scale;
    const innerInnerRadius = 15 * scale;

    let hoveredSlice = null;

    function getMousePos(evt) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        return {
            x: (evt.clientX - rect.left) * scaleX,
            y: (evt.clientY - rect.top) * scaleY
        };
    }

    function normalizeAngle(angle) {
        while (angle < 0) angle += 2 * Math.PI;
        while (angle >= 2 * Math.PI) angle -= 2 * Math.PI;
        return angle;
    }

    function isPointInArc(x, y, cx, cy, outerR, innerR, startAngle, endAngle) {
        const dx = x - cx;
        const dy = y - cy;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < innerR || dist > outerR) return false;
        
        let angle = Math.atan2(dy, dx);
        if (angle < -Math.PI / 2) angle += 2 * Math.PI;
        
        let start = startAngle;
        if (start < -Math.PI / 2) start += 2 * Math.PI;
        let end = endAngle;
        if (end < -Math.PI / 2) end += 2 * Math.PI;
        
        if (start <= end) {
            return angle >= start && angle <= end;
        } else {
            return angle >= start || angle <= end;
        }
    }

    function drawChart(hoveredItem = null) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        if (platformData && platformData.length > 0) {
            const totalOuter = platformData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            platformData.forEach((item, index) => {
                const sliceAngle = (item.count / totalOuter) * 2 * Math.PI;
                const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
                
                let offsetX = 0, offsetY = 0;
                if (hoveredItem && hoveredItem.type === 'platform' && hoveredItem.index === index) {
                    const midAngle = currentAngle + sliceAngle / 2;
                    offsetX = Math.cos(midAngle) * 5 * scale;
                    offsetY = Math.sin(midAngle) * 5 * scale;
                }
                
                ctx.beginPath();
                ctx.arc(centerX + offsetX, centerY + offsetY, outerOuterRadius, currentAngle, currentAngle + sliceAngle);
                ctx.arc(centerX + offsetX, centerY + offsetY, outerInnerRadius, currentAngle + sliceAngle, currentAngle, true);
                ctx.closePath();
                ctx.fillStyle = color;
                ctx.fill();
                
                currentAngle += sliceAngle;
            });
        }
        
        if (browserData && browserData.length > 0) {
            const totalInner = browserData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            browserData.forEach((item, index) => {
                const sliceAngle = (item.count / totalInner) * 2 * Math.PI;
                const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
                
                let offsetX = 0, offsetY = 0;
                if (hoveredItem && hoveredItem.type === 'browser' && hoveredItem.index === index) {
                    const midAngle = currentAngle + sliceAngle / 2;
                    offsetX = Math.cos(midAngle) * 4 * scale;
                    offsetY = Math.sin(midAngle) * 4 * scale;
                }
                
                ctx.beginPath();
                ctx.arc(centerX + offsetX, centerY + offsetY, innerOuterRadius, currentAngle, currentAngle + sliceAngle);
                ctx.arc(centerX + offsetX, centerY + offsetY, innerInnerRadius, currentAngle + sliceAngle, currentAngle, true);
                ctx.closePath();
                ctx.fillStyle = color;
                ctx.fill();
                
                currentAngle += sliceAngle;
            });
        }
        
        ctx.beginPath();
        ctx.arc(centerX, centerY, innerInnerRadius - 2, 0, 2 * Math.PI);
        ctx.fillStyle = '#fff';
        ctx.fill();
    }

    function showTooltip(e, data, percent) {
        let tooltip = document.getElementById('chart-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'chart-tooltip';
            tooltip.style.cssText = `
                position: fixed;
                background: #fff;
                color: #333;
                padding: 8px 14px;
                border-radius: 6px;
                font-size: 13px;
                pointer-events: none;
                z-index: 10000;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            `;
            document.body.appendChild(tooltip);
        }
        
        tooltip.innerHTML = `<strong>${data.name}</strong><br>数量: ${data.count} (${percent}%)`;
        tooltip.style.left = (e.clientX + 15) + 'px';
        tooltip.style.top = (e.clientY - 10) + 'px';
        tooltip.style.display = 'block';
    }

    function hideTooltip() {
        const tooltip = document.getElementById('chart-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    }

    canvas.onmousemove = function(e) {
        const pos = getMousePos(e);
        
        let found = null;
        
        if (platformData && platformData.length > 0) {
            const totalOuter = platformData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            for (let i = 0; i < platformData.length; i++) {
                const sliceAngle = (platformData[i].count / totalOuter) * 2 * Math.PI;
                const endAngle = currentAngle + sliceAngle;
                
                if (isPointInArc(pos.x, pos.y, centerX, centerY, outerOuterRadius, outerInnerRadius, currentAngle, endAngle)) {
                    const percent = Math.round((platformData[i].count / totalOuter) * 100);
                    found = { type: 'platform', index: i, data: platformData[i], percent };
                    break;
                }
                currentAngle = endAngle;
            }
        }
        
        if (!found && browserData && browserData.length > 0) {
            const totalInner = browserData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            for (let i = 0; i < browserData.length; i++) {
                const sliceAngle = (browserData[i].count / totalInner) * 2 * Math.PI;
                const endAngle = currentAngle + sliceAngle;
                
                if (isPointInArc(pos.x, pos.y, centerX, centerY, innerOuterRadius, innerInnerRadius, currentAngle, endAngle)) {
                    const percent = Math.round((browserData[i].count / totalInner) * 100);
                    found = { type: 'browser', index: i, data: browserData[i], percent };
                    break;
                }
                currentAngle = endAngle;
            }
        }
        
        if (found) {
            canvas.style.cursor = 'pointer';
            drawChart(found);
            showTooltip(e, found.data, found.percent);
            hoveredSlice = found;
        } else {
            canvas.style.cursor = 'default';
            drawChart(null);
            hideTooltip();
            hoveredSlice = null;
        }
    };

    canvas.onmouseleave = function() {
        hideTooltip();
        hoveredSlice = null;
        drawChart(null);
    };

    canvas.onclick = function(e) {
        if (hoveredSlice) {
            showTooltip(e, hoveredSlice.data, hoveredSlice.percent);
        }
    };

    drawChart();
}

async function openClientModal(event) {
    event.preventDefault();
    
    const modal = document.getElementById('clientDetailModal');
    modal.classList.remove('modal-hidden');
    
    try {
        // 重新获取完整数据（limit=0表示不限制）
        const response = await fetch('/api/client-stats?limit=0');
        fullClientStats = await response.json();
        
        if (!fullClientStats.success) {
            showAlert('提示', '获取客户端数据失败');
            return;
        }
        
        // 绘制大尺寸同心圆饼图
        drawModalNestedDonutChart('clientModalDonutChart', fullClientStats.platforms, fullClientStats.browsers);
        
        // 渲染完整列表
        renderClientModalList();
    } catch (error) {
        console.error('获取客户端数据失败:', error);
        showAlert('提示', '获取客户端数据失败');
    }
}

function closeClientModal() {
    const modal = document.getElementById('clientDetailModal');
    modal.classList.add('modal-hidden');
}

function drawModalNestedDonutChart(canvasId, platformData, browserData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const scale = centerX / 90;
    
    const outerOuterRadius = 75 * scale;
    const outerInnerRadius = 55 * scale;
    const innerOuterRadius = 38 * scale;
    const innerInnerRadius = 18 * scale;
    
    const rankColors = ['#FF6B6B', '#FFA726', '#FFD93D', '#6BCB77', '#4D96FF'];

    let hoveredSlice = null;

    function getMousePos(evt) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        return {
            x: (evt.clientX - rect.left) * scaleX,
            y: (evt.clientY - rect.top) * scaleY
        };
    }

    function isPointInArc(x, y, cx, cy, outerR, innerR, startAngle, endAngle) {
        const dx = x - cx;
        const dy = y - cy;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < innerR || dist > outerR) return false;
        
        let angle = Math.atan2(dy, dx);
        if (angle < -Math.PI / 2) angle += 2 * Math.PI;
        
        let start = startAngle;
        if (start < -Math.PI / 2) start += 2 * Math.PI;
        let end = endAngle;
        if (end < -Math.PI / 2) end += 2 * Math.PI;
        
        if (start <= end) {
            return angle >= start && angle <= end;
        } else {
            return angle >= start || angle <= end;
        }
    }

    function drawChart(hoveredItem = null) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        if (platformData && platformData.length > 0) {
            const totalOuter = platformData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            platformData.forEach((item, index) => {
                const sliceAngle = (item.count / totalOuter) * 2 * Math.PI;
                const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
                
                let offsetX = 0, offsetY = 0;
                if (hoveredItem && hoveredItem.type === 'platform' && hoveredItem.index === index) {
                    const midAngle = currentAngle + sliceAngle / 2;
                    offsetX = Math.cos(midAngle) * 5 * scale;
                    offsetY = Math.sin(midAngle) * 5 * scale;
                }
                
                ctx.beginPath();
                ctx.arc(centerX + offsetX, centerY + offsetY, outerOuterRadius, currentAngle, currentAngle + sliceAngle);
                ctx.arc(centerX + offsetX, centerY + offsetY, outerInnerRadius, currentAngle + sliceAngle, currentAngle, true);
                ctx.closePath();
                ctx.fillStyle = color;
                ctx.fill();
                
                currentAngle += sliceAngle;
            });
        }
        
        if (browserData && browserData.length > 0) {
            const totalInner = browserData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            browserData.forEach((item, index) => {
                const sliceAngle = (item.count / totalInner) * 2 * Math.PI;
                const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
                
                let offsetX = 0, offsetY = 0;
                if (hoveredItem && hoveredItem.type === 'browser' && hoveredItem.index === index) {
                    const midAngle = currentAngle + sliceAngle / 2;
                    offsetX = Math.cos(midAngle) * 4 * scale;
                    offsetY = Math.sin(midAngle) * 4 * scale;
                }
                
                ctx.beginPath();
                ctx.arc(centerX + offsetX, centerY + offsetY, innerOuterRadius, currentAngle, currentAngle + sliceAngle);
                ctx.arc(centerX + offsetX, centerY + offsetY, innerInnerRadius, currentAngle + sliceAngle, currentAngle, true);
                ctx.closePath();
                ctx.fillStyle = color;
                ctx.fill();
                
                currentAngle += sliceAngle;
            });
        }
        
        ctx.beginPath();
        ctx.arc(centerX, centerY, innerInnerRadius - 2, 0, 2 * Math.PI);
        ctx.fillStyle = '#fff';
        ctx.fill();
    }

    function showTooltip(e, data, percent) {
        let tooltip = document.getElementById('chart-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'chart-tooltip';
            tooltip.style.cssText = `
                position: fixed;
                background: #fff;
                color: #333;
                padding: 8px 14px;
                border-radius: 6px;
                font-size: 13px;
                pointer-events: none;
                z-index: 10000;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            `;
            document.body.appendChild(tooltip);
        }
        
        tooltip.innerHTML = `<strong>${data.name}</strong><br>数量: ${data.count} (${percent}%)`;
        tooltip.style.left = (e.clientX + 15) + 'px';
        tooltip.style.top = (e.clientY - 10) + 'px';
        tooltip.style.display = 'block';
    }

    function hideTooltip() {
        const tooltip = document.getElementById('chart-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    }

    canvas.onmousemove = function(e) {
        const pos = getMousePos(e);
        
        let found = null;
        
        if (platformData && platformData.length > 0) {
            const totalOuter = platformData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            for (let i = 0; i < platformData.length; i++) {
                const sliceAngle = (platformData[i].count / totalOuter) * 2 * Math.PI;
                const endAngle = currentAngle + sliceAngle;
                
                if (isPointInArc(pos.x, pos.y, centerX, centerY, outerOuterRadius, outerInnerRadius, currentAngle, endAngle)) {
                    const percent = Math.round((platformData[i].count / totalOuter) * 100);
                    found = { type: 'platform', index: i, data: platformData[i], percent };
                    break;
                }
                currentAngle = endAngle;
            }
        }
        
        if (!found && browserData && browserData.length > 0) {
            const totalInner = browserData.reduce((sum, item) => sum + item.count, 0);
            let currentAngle = -Math.PI / 2;
            
            for (let i = 0; i < browserData.length; i++) {
                const sliceAngle = (browserData[i].count / totalInner) * 2 * Math.PI;
                const endAngle = currentAngle + sliceAngle;
                
                if (isPointInArc(pos.x, pos.y, centerX, centerY, innerOuterRadius, innerInnerRadius, currentAngle, endAngle)) {
                    const percent = Math.round((browserData[i].count / totalInner) * 100);
                    found = { type: 'browser', index: i, data: browserData[i], percent };
                    break;
                }
                currentAngle = endAngle;
            }
        }
        
        if (found) {
            canvas.style.cursor = 'pointer';
            drawChart(found);
            showTooltip(e, found.data, found.percent);
            hoveredSlice = found;
        } else {
            canvas.style.cursor = 'default';
            drawChart(null);
            hideTooltip();
            hoveredSlice = null;
        }
    };

    canvas.onmouseleave = function() {
        hideTooltip();
        hoveredSlice = null;
        drawChart(null);
    };

    canvas.onclick = function(e) {
        if (hoveredSlice) {
            showTooltip(e, hoveredSlice.data, hoveredSlice.percent);
        }
    };

    drawChart();
}

function renderClientModalList() {
    const rankColors = ['#FF6B6B', '#FFA726', '#FFD93D', '#6BCB77', '#4D96FF'];
    const platforms = fullClientStats.platforms || [];
    const browsers = fullClientStats.browsers || [];
    
    const platformsContainer = document.getElementById('clientModalPlatforms');
    const browsersContainer = document.getElementById('clientModalBrowsers');
    
    // 渲染平台列表
    platformsContainer.innerHTML = platforms.map((item, index) => {
        const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
        return `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #f0f0f0;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <div style="width: 10px; height: 10px; border-radius: 50%; background: ${color};"></div>
                    <span style="color: var(--text-primary); font-size: 14px;">${item.name}</span>
                </div>
                <span style="color: #000; font-weight: 600; font-size: 14px;">${formatNumber(item.count)}</span>
            </div>
        `;
    }).join('');
    
    // 渲染浏览器列表
    browsersContainer.innerHTML = browsers.map((item, index) => {
        const color = index < rankColors.length ? rankColors[index] : '#4D96FF';
        return `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #f0f0f0;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <div style="width: 10px; height: 10px; border-radius: 50%; background: ${color};"></div>
                    <span style="color: var(--text-primary); font-size: 14px;">${item.name}</span>
                </div>
                <span style="color: #000; font-weight: 600; font-size: 14px;">${formatNumber(item.count)}</span>
            </div>
        `;
    }).join('');
}

function renderQPSChart() {
    const chartContainer = document.getElementById('qps-chart');
    if (!chartContainer) {
        console.log('QPS图表容器不存在');
        return;
    }

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        console.log('QPS图表容器不可见，宽高:', rect.width, rect.height);
        return;
    }

    console.log('开始渲染QPS图表');

    if (!qpsChart) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        qpsChart = echarts.init(chartContainer);
        // 计算尺寸
        qpsChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (qpsChart) {
                qpsChart.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        qpsChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const qpsHistory = historyData.qpsHistory || [];
    console.log('QPS历史数据长度:', qpsHistory.length);
    
    const maxBars = 35;
    const displayHistory = qpsHistory.slice(-maxBars);
    
    const paddingCount = maxBars - displayHistory.length;
    const paddedHistory = [
        ...Array(paddingCount).fill({ time: '', qps: 0 }),
        ...displayHistory
    ];
    
    const times = paddedHistory.map(d => d.time || '');
    const displayValues = paddedHistory.map(d => d.qps || 0);
    const originalValues = [...displayValues];
    
    const maxQPS = Math.max(...displayValues, 1);
    const minVisibleValue = maxQPS * 0.05;
    const values = displayValues.map(v => v === 0 ? minVisibleValue : v);
    
    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'shadow'
            },
            backgroundColor: 'rgba(255, 255, 255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    const dataIndex = param.dataIndex;
                    const originalValue = originalValues[dataIndex];
                    return `时间: ${param.axisValue}<br/>QPS: ${originalValue}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxQPS * 1.1,
            scale: false
        },
        series: [
            {
                type: 'bar',
                data: values,
                barCategoryGap:'50%',
                itemStyle: {
                    borderRadius: [2, 2, 0, 0],
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: '#1a73e8' },
                        { offset: 1, color: '#4285f4' }
                    ])
                },
                emphasis: {
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#4285f4' },
                            { offset: 1, color: '#669df6' }
                        ])
                    }
                },
                animationDuration: 300,
                animationEasing: 'cubicOut'
            }
        ]
    };
    
    qpsChart.setOption(option);
}

function renderQPSChartMobile() {
    const chartContainer = document.getElementById('qps-chart-mobile');
    if (!chartContainer) return;

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        return;
    }

    if (!window.qpsChartMobile) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.qpsChartMobile = echarts.init(chartContainer);
        // 计算尺寸
        window.qpsChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.qpsChartMobile) {
                window.qpsChartMobile.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.qpsChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const qpsHistory = historyData.qpsHistory || [];
    const maxBars = 35;
    const displayHistory = qpsHistory.slice(-maxBars);

    const paddingCount = maxBars - displayHistory.length;
    const paddedHistory = [
        ...Array(paddingCount).fill({ time: '', qps: 0 }),
        ...displayHistory
    ];

    const times = paddedHistory.map(d => d.time || '');
    const displayValues = paddedHistory.map(d => d.qps || 0);
    const originalValues = [...displayValues];

    const maxQPS = Math.max(...displayValues, 1);
    const minVisibleValue = maxQPS * 0.05;
    const values = displayValues.map(v => v === 0 ? minVisibleValue : v);

    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'shadow'
            },
            backgroundColor: 'rgba(255, 255, 255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    const dataIndex = param.dataIndex;
                    const originalValue = originalValues[dataIndex];
                    return `时间: ${param.axisValue}<br/>QPS: ${originalValue}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxQPS * 1.1,
            scale: false
        },
        series: [
            {
                type: 'bar',
                data: values,
                barCategoryGap: '50%',
                itemStyle: {
                    borderRadius: [2, 2, 0, 0],
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: '#1a73e8' },
                        { offset: 1, color: '#4285f4' }
                    ])
                },
                emphasis: {
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#4285f4' },
                            { offset: 1, color: '#669df6' }
                        ])
                    }
                },
                animationDuration: 300,
                animationEasing: 'cubicOut'
            }
        ]
    };

    window.qpsChartMobile.setOption(option);
}

function renderTrafficChart() {
    const chartContainer = document.getElementById('traffic-chart');
    if (!chartContainer) return;
    
    const trafficHistory = historyData.trafficHistory || [];
    
    const lastInbound = trafficHistory[trafficHistory.length - 1]?.inbound || 0;
    const lastOutbound = trafficHistory[trafficHistory.length - 1]?.outbound || 0;
    
    const formatSpeed = (bytes) => {
        if (bytes >= 1024 * 1024) {
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB/s';
        } else if (bytes >= 1024) {
            return (bytes / 1024).toFixed(2) + ' KB/s';
        }
        return bytes + ' B/s';
    };
    
    const inboundSpeedEl = document.getElementById('inboundSpeed');
    const outboundSpeedEl = document.getElementById('outboundSpeed');
    
    if (inboundSpeedEl) inboundSpeedEl.textContent = formatSpeed(lastInbound);
    if (outboundSpeedEl) outboundSpeedEl.textContent = formatSpeed(lastOutbound);
    
    const inboundSpeedMobileEl = document.getElementById('inboundSpeed-mobile');
    const outboundSpeedMobileEl = document.getElementById('outboundSpeed-mobile');
    if (inboundSpeedMobileEl) inboundSpeedMobileEl.textContent = formatSpeed(lastInbound);
    if (outboundSpeedMobileEl) outboundSpeedMobileEl.textContent = formatSpeed(lastOutbound);

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        return;
    }

    if (!window.trafficChart) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.trafficChart = echarts.init(chartContainer);
        // 计算尺寸
        window.trafficChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.trafficChart) {
                window.trafficChart.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.trafficChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const maxBars = 35;
    const displayHistory = trafficHistory.slice(-maxBars);
    
    const times = displayHistory.map(d => d.time || '');
    const inboundValues = displayHistory.map(d => d.inbound || 0);
    const outboundValues = displayHistory.map(d => d.outbound || 0);
    
    const maxTraffic = Math.max(...inboundValues, ...outboundValues, 1);
    const minVisibleValue = maxTraffic * 0.1;
    const displayInboundValues = inboundValues.map(v => v === 0 ? minVisibleValue : v);
    const displayOutboundValues = outboundValues.map(v => v === 0 ? minVisibleValue : v);
    
    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'line'
            },
            backgroundColor: 'rgba(255,255,255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    const dataIndex = param.dataIndex;
                    const inboundValue = inboundValues[dataIndex];
                    const outboundValue = outboundValues[dataIndex];
                    return `时间: ${param.axisValue}<br/>入站: ${formatSpeed(inboundValue)}<br/>出站: ${formatSpeed(outboundValue)}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxTraffic * 1.1
        },
        series: [
            {
                name: '入站',
                type: 'line',
                data: displayInboundValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#1a73e8'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(26, 115, 232, 0.4)' },
                        { offset: 1, color: 'rgba(26, 115, 232, 0.1)' }
                    ])
                }
            },
            {
                name: '出站',
                type: 'line',
                data: displayOutboundValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#34a853'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(52, 168, 83, 0.4)' },
                        { offset: 1, color: 'rgba(52, 168, 83, 0.1)' }
                    ])
                }
            }
        ]
    };
    
    window.trafficChart.setOption(option);
}

function renderTrafficChartMobile() {
    const chartContainer = document.getElementById('traffic-chart-mobile');
    if (!chartContainer) return;

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        return;
    }

    if (!window.trafficChartMobile) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.trafficChartMobile = echarts.init(chartContainer);
        // 计算尺寸
        window.trafficChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.trafficChartMobile) {
                window.trafficChartMobile.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.trafficChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const trafficHistory = historyData.trafficHistory || [];
    const maxBars = 35;
    const displayHistory = trafficHistory.slice(-maxBars);

    const times = displayHistory.map(d => d.time || '');
    const inboundValues = displayHistory.map(d => d.inbound || 0);
    const outboundValues = displayHistory.map(d => d.outbound || 0);

    const maxTraffic = Math.max(...inboundValues, ...outboundValues, 1);
    const minVisibleValue = maxTraffic * 0.1;
    const displayInboundValues = inboundValues.map(v => v === 0 ? minVisibleValue : v);
    const displayOutboundValues = outboundValues.map(v => v === 0 ? minVisibleValue : v);

    const formatSpeed = (bytes) => {
        if (bytes >= 1024 * 1024) {
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB/s';
        } else if (bytes >= 1024) {
            return (bytes / 1024).toFixed(2) + ' KB/s';
        }
        return bytes + ' B/s';
    };

    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'line'
            },
            backgroundColor: 'rgba(255,255,255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    const dataIndex = param.dataIndex;
                    const inboundValue = inboundValues[dataIndex];
                    const outboundValue = outboundValues[dataIndex];
                    return `时间: ${param.axisValue}<br/>入站: ${formatSpeed(inboundValue)}<br/>出站: ${formatSpeed(outboundValue)}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxTraffic * 1.1
        },
        series: [
            {
                name: '入站',
                type: 'line',
                data: displayInboundValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#1a73e8'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(26, 115, 232, 0.4)' },
                        { offset: 1, color: 'rgba(26, 115, 232, 0.1)' }
                    ])
                }
            },
            {
                name: '出站',
                type: 'line',
                data: displayOutboundValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#34a853'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(52, 168, 83, 0.4)' },
                        { offset: 1, color: 'rgba(52, 168, 83, 0.1)' }
                    ])
                }
            }
        ]
    };

    window.trafficChartMobile.setOption(option);
}

function renderAttackChart() {
    const chartContainer = document.getElementById('attack-chart');
    if (!chartContainer) return;

    const attackHistory = historyData.attackHistory || [];

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        return;
    }

    if (!window.attackChart) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.attackChart = echarts.init(chartContainer);
        // 计算尺寸
        window.attackChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.attackChart) {
                window.attackChart.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.attackChart.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const maxBars = 35;
    const displayHistory = attackHistory.slice(-maxBars);
    
    const times = displayHistory.map(d => d.time || '');
    const attackValues = displayHistory.map(d => d.count || 0);
    
    const maxAttack = Math.max(...attackValues, 1);
    
    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'line'
            },
            backgroundColor: 'rgba(255,255,255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    return `时间: ${param.axisValue}<br/>攻击: ${param.value}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxAttack * 1.1
        },
        series: [
            {
                name: '攻击',
                type: 'line',
                data: attackValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#ef4444'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(239, 68, 68, 0.4)' },
                        { offset: 1, color: 'rgba(239, 68, 68, 0.1)' }
                    ])
                }
            }
        ]
    };
    
    window.attackChart.setOption(option);
}

function renderAttackChartMobile() {
    const chartContainer = document.getElementById('attack-chart-mobile');
    if (!chartContainer) return;

    const rect = chartContainer.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        return;
    }

    if (!window.attackChartMobile) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.attackChartMobile = echarts.init(chartContainer);
        // 计算尺寸
        window.attackChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.attackChartMobile) {
                window.attackChartMobile.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.attackChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    const attackHistory = historyData.attackHistory || [];
    const maxBars = 35;
    const displayHistory = attackHistory.slice(-maxBars);

    const times = displayHistory.map(d => d.time || '');
    const attackValues = displayHistory.map(d => d.count || 0);

    const maxAttack = Math.max(...attackValues, 1);

    const option = {
        grid: {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            containLabel: false
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'line'
            },
            backgroundColor: 'rgba(255,255,255, 0.95)',
            borderColor: '#e8eaed',
            borderWidth: 1,
            padding: [8, 12],
            textStyle: {
                color: '#202124',
                fontSize: 12
            },
            formatter: function(params) {
                if (params && params.length > 0) {
                    const param = params[0];
                    return `时间: ${param.axisValue}<br/>攻击: ${param.value}`;
                }
                return '';
            }
        },
        xAxis: {
            type: 'category',
            data: times,
            show: false,
            boundaryGap: true
        },
        yAxis: {
            type: 'value',
            show: false,
            min: 0,
            max: maxAttack * 1.1
        },
        series: [
            {
                name: '攻击',
                type: 'line',
                data: attackValues,
                smooth: true,
                showSymbol: false,
                lineStyle: {
                    width: 2,
                    color: '#ef4444'
                },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(239, 68, 68, 0.4)' },
                        { offset: 1, color: 'rgba(239, 68, 68, 0.1)' }
                    ])
                }
            }
        ]
    };

    window.attackChartMobile.setOption(option);
}

async function renderTrendChart() {
    const chartContainer = document.getElementById('trend-chart');
    if (!chartContainer) return;

    const activeTab = document.querySelector('.trend-tab.active')?.dataset.tab || 'ip';
    const compareType = document.querySelector('input[name="compare"]:checked')?.value || 'prev-day';

    try {
        const response = await fetch(`/api/trend-data?compare=${compareType}`);
        const result = await response.json();
        
        if (!result.success || !result.data) {
            throw new Error('获取趋势数据失败');
        }

        if (!window.trendChart) {
            window.trendChart = echarts.init(chartContainer);
            window.addEventListener('resize', () => {
                if (window.trendChart) {
                    window.trendChart.resize();
                }
            });
        } else {
            window.trendChart.resize();
        }

        const todayTrend = result.data.todayTrend || [];
        const compareTrend = result.data.compareTrend || [];

        const hours = [];
        const todayIPData = [];
        const compareIPData = [];
        const todayBlockData = [];
        const todayObserveData = [];
        const compareBlockData = [];
        const compareObserveData = [];

        for (let i = 0; i < 24; i++) {
            hours.push(`${i.toString().padStart(2, '0')}:00`);
            
            const today = todayTrend[i] || { abnormal_ip_count: 0, block_count: 0, observe_count: 0 };
            const compare = compareTrend[i] || { abnormal_ip_count: 0, block_count: 0, observe_count: 0 };
            
            todayIPData.push(today.abnormal_ip_count || 0);
            compareIPData.push(compare.abnormal_ip_count || 0);
            todayBlockData.push(today.block_count || 0);
            todayObserveData.push(today.observe_count || 0);
            compareBlockData.push(compare.block_count || 0);
            compareObserveData.push(compare.observe_count || 0);
        }

        const option = {
            grid: {
                left: '3%',
                right: '4%',
                bottom: '3%',
                top: '10%',
                containLabel: true
            },
            tooltip: {
                trigger: 'axis',
                axisPointer: {
                    type: 'cross',
                    crossStyle: {
                        color: '#999'
                    }
                },
                backgroundColor: 'rgba(255,255,255, 0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                }
            },
            legend: {
                data: activeTab === 'ip' ? ['今日IP异常', compareType === 'prev-day' ? '前一日' : '上周同期'] : ['拦截', '观察', compareType === 'prev-day' ? '前一日拦截' : '上周同期拦截', compareType === 'prev-day' ? '前一日观察' : '上周同期观察'],
                top: 0,
                textStyle: {
                    fontSize: 12,
                    color: '#5f6368'
                }
            },
            xAxis: {
                type: 'category',
                data: hours,
                axisLine: {
                    lineStyle: {
                        color: '#e0e0e0'
                    }
                },
                axisLabel: {
                    fontSize: 11,
                    color: '#80868b',
                    interval: 2
                },
                axisTick: {
                    show: false
                }
            },
            yAxis: {
                type: 'value',
                axisLine: {
                    show: false
                },
                axisTick: {
                    show: false
                },
                axisLabel: {
                    fontSize: 11,
                    color: '#80868b'
                },
                splitLine: {
                    lineStyle: {
                        color: '#f1f3f4',
                        type: 'dashed'
                    }
                }
            },
            series: activeTab === 'ip' ? [
                {
                    name: '今日IP异常',
                    type: 'line',
                    data: todayIPData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#6366f1'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(99, 102, 241, 0.3)' },
                            { offset: 1, color: 'rgba(99, 102, 241, 0.05)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日' : '上周同期',
                    type: 'line',
                    data: compareIPData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#a5b4fc'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(165, 180, 252, 0.2)' },
                            { offset: 1, color: 'rgba(165, 180, 252, 0.02)' }
                        ])
                    }
                }
            ] : [
                {
                    name: '拦截',
                    type: 'line',
                    data: todayBlockData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#ef4444'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(239, 68, 68, 0.3)' },
                            { offset: 1, color: 'rgba(239, 68, 68, 0.05)' }
                        ])
                    }
                },
                {
                    name: '观察',
                    type: 'line',
                    data: todayObserveData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#f59e0b'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(245, 158, 11, 0.3)' },
                            { offset: 1, color: 'rgba(245, 158, 11, 0.05)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日拦截' : '上周同期拦截',
                    type: 'line',
                    data: compareBlockData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#fca5a5'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(252, 165, 165, 0.2)' },
                            { offset: 1, color: 'rgba(252, 165, 165, 0.02)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日观察' : '上周同期观察',
                    type: 'line',
                    data: compareObserveData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#fcd34d'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(252, 211, 77, 0.2)' },
                            { offset: 1, color: 'rgba(252, 211, 77, 0.02)' }
                        ])
                    }
                }
            ]
        };

        window.trendChart.setOption(option, true);
    } catch (error) {
        console.error('加载趋势数据失败:', error);
    }
}

function bindTrendEvents() {
    const tabs = document.querySelectorAll('.trend-tab');
    const radios = document.querySelectorAll('input[name="compare"]');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            requestAnimationFrame(() => {
                renderTrendChart();
                renderTrendChartMobile();
            });
        });
    });

    radios.forEach(radio => {
        radio.addEventListener('change', () => {
            renderTrendChart();
            renderTrendChartMobile();
        });
    });
}

async function renderTrendChartMobile() {
    const chartContainer = document.getElementById('trend-chart-mobile');
    if (!chartContainer) return;

    const activeTab = document.querySelector('.trend-tab.active')?.dataset.tab || 'ip';
    const compareType = document.querySelector('input[name="compare"]:checked')?.value || 'prev-day';

    if (!window.trendChartMobile) {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        window.trendChartMobile = echarts.init(chartContainer);
        // 计算尺寸
        window.trendChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
        window.addEventListener('resize', () => {
            if (window.trendChartMobile) {
                window.trendChartMobile.resize();
            }
        });
    } else {
        // 先隐藏
        chartContainer.style.opacity = '0';
        chartContainer.style.visibility = 'hidden';
        // 计算尺寸
        window.trendChartMobile.resize();
        // 显示回来
        chartContainer.style.visibility = 'visible';
        chartContainer.style.opacity = '1';
    }

    try {
        const response = await fetch(`/api/trend-data?compare=${compareType}`);
        const result = await response.json();

        if (!result.success || !result.data) {
            throw new Error('获取趋势数据失败');
        }

        const todayTrend = result.data.todayTrend || [];
        const compareTrend = result.data.compareTrend || [];

        const hours = [];
        const todayIPData = [];
        const compareIPData = [];
        const todayBlockData = [];
        const todayObserveData = [];
        const compareBlockData = [];
        const compareObserveData = [];

        for (let i = 0; i < 24; i++) {
            hours.push(`${i.toString().padStart(2, '0')}:00`);

            const today = todayTrend[i] || { abnormal_ip_count: 0, block_count: 0, observe_count: 0 };
            const compare = compareTrend[i] || { abnormal_ip_count: 0, block_count: 0, observe_count: 0 };

            todayIPData.push(today.abnormal_ip_count || 0);
            compareIPData.push(compare.abnormal_ip_count || 0);
            todayBlockData.push(today.block_count || 0);
            todayObserveData.push(today.observe_count || 0);
            compareBlockData.push(compare.block_count || 0);
            compareObserveData.push(compare.observe_count || 0);
        }

        const option = {
            grid: {
                left: '3%',
                right: '4%',
                bottom: '3%',
                top: '10%',
                containLabel: true
            },
            tooltip: {
                trigger: 'axis',
                axisPointer: {
                    type: 'cross',
                    crossStyle: {
                        color: '#999'
                    }
                },
                backgroundColor: 'rgba(255,255,255, 0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                }
            },
            legend: {
                data: activeTab === 'ip' ? ['今日IP异常', compareType === 'prev-day' ? '前一日' : '上周同期'] : ['拦截', '观察', compareType === 'prev-day' ? '前一日拦截' : '上周同期拦截'],
                top: 0,
                textStyle: {
                    fontSize: 10,
                    color: '#5f6368'
                }
            },
            xAxis: {
                type: 'category',
                data: hours,
                axisLine: {
                    lineStyle: {
                        color: '#e0e0e0'
                    }
                },
                axisLabel: {
                    fontSize: 10,
                    color: '#80868b',
                    interval: 5
                },
                axisTick: {
                    show: false
                }
            },
            yAxis: {
                type: 'value',
                axisLine: {
                    show: false
                },
                axisTick: {
                    show: false
                },
                axisLabel: {
                    fontSize: 10,
                    color: '#80868b'
                },
                splitLine: {
                    lineStyle: {
                        color: '#f1f3f4',
                        type: 'dashed'
                    }
                }
            },
            series: activeTab === 'ip' ? [
                {
                    name: '今日IP异常',
                    type: 'line',
                    data: todayIPData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#6366f1'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(99, 102, 241, 0.3)' },
                            { offset: 1, color: 'rgba(99, 102, 241, 0.05)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日' : '上周同期',
                    type: 'line',
                    data: compareIPData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#a5b4fc'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(165, 180, 252, 0.2)' },
                            { offset: 1, color: 'rgba(165, 180, 252, 0.02)' }
                        ])
                    }
                }
            ] : [
                {
                    name: '拦截',
                    type: 'line',
                    data: todayBlockData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#ef4444'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(239, 68, 68, 0.3)' },
                            { offset: 1, color: 'rgba(239, 68, 68, 0.05)' }
                        ])
                    }
                },
                {
                    name: '观察',
                    type: 'line',
                    data: todayObserveData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#f59e0b'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(245, 158, 11, 0.3)' },
                            { offset: 1, color: 'rgba(245, 158, 11, 0.05)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日拦截' : '上周同期拦截',
                    type: 'line',
                    data: compareBlockData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#fca5a5'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(252, 165, 165, 0.2)' },
                            { offset: 1, color: 'rgba(252, 165, 165, 0.02)' }
                        ])
                    }
                },
                {
                    name: compareType === 'prev-day' ? '前一日观察' : '上周同期观察',
                    type: 'line',
                    data: compareObserveData,
                    smooth: true,
                    showSymbol: false,
                    lineStyle: {
                        width: 2,
                        color: '#fcd34d'
                    },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: 'rgba(252, 211, 77, 0.2)' },
                            { offset: 1, color: 'rgba(252, 211, 77, 0.02)' }
                        ])
                    }
                }
            ]
        };

        window.trendChartMobile.setOption(option, true);
    } catch (error) {
        console.error('加载趋势数据失败:', error);
    }
}

function renderGeoDistribution() {
    const geoContainer = document.getElementById('geoDistribution');
    if (!geoContainer) return;
    
    let geoData = {};
    
    if (currentActionTab === 'access') {
        if (currentGeoTab === 'china') {
            geoData = statsData.accessProvinceDistribution || {};
        } else {
            geoData = statsData.accessGeoDistribution || {};
        }
    } else if (currentActionTab === 'detected') {
        if (currentGeoTab === 'china') {
            geoData = statsData.detectedProvinceDistribution || {};
        } else {
            geoData = statsData.detectedGeoDistribution || {};
        }
    } else if (currentActionTab === 'blocked') {
        if (currentGeoTab === 'china') {
            geoData = statsData.blockedProvinceDistribution || {};
        } else {
            geoData = statsData.blockedGeoDistribution || {};
        }
    }
    
    const sortedGeo = Object.entries(geoData).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const maxGeo = sortedGeo.length > 0 ? sortedGeo[0][1] : 1;
    
    if (sortedGeo.length === 0) {
        geoContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; width: 100%; text-align: center; color: var(--text-muted);">暂无数据</div>';
    } else {
        geoContainer.innerHTML = `
            <div style="width: 100%;">
                ${sortedGeo.map(([name, count]) => `
                    <div style="margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                            <span style="font-size: 13px; color: var(--text-secondary);">${name}</span>
                            <span style="font-size: 13px; font-weight: 600; color: var(--primary-blue);">${formatNumber(count)}</span>
                        </div>
                        <div style="height: 6px; background: var(--light-blue); border-radius: 3px; overflow: hidden;">
                            <div style="height: 100%; background: var(--primary-blue); border-radius: 3px; width: ${(count / maxGeo) * 100}%;"></div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    renderGeoMap(geoData);
}

function renderGeoDistributionMobile() {
    const geoContainer = document.getElementById('geoDistribution-mobile');
    if (!geoContainer) return;

    let geoData = {};

    if (currentActionTab === 'access') {
        if (currentGeoTab === 'china') {
            geoData = statsData.accessProvinceDistribution || {};
        } else {
            geoData = statsData.accessGeoDistribution || {};
        }
    } else if (currentActionTab === 'detected') {
        if (currentGeoTab === 'china') {
            geoData = statsData.detectedProvinceDistribution || {};
        } else {
            geoData = statsData.detectedGeoDistribution || {};
        }
    } else if (currentActionTab === 'blocked') {
        if (currentGeoTab === 'china') {
            geoData = statsData.blockedProvinceDistribution || {};
        } else {
            geoData = statsData.blockedGeoDistribution || {};
        }
    }

    const sortedGeo = Object.entries(geoData).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const maxGeo = sortedGeo.length > 0 ? sortedGeo[0][1] : 1;

    if (sortedGeo.length === 0) {
        geoContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; width: 100%; text-align: center; color: var(--text-muted);">暂无数据</div>';
    } else {
        geoContainer.innerHTML = `
            <div style="width: 100%;">
                ${sortedGeo.map(([name, count]) => `
                    <div style="margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                            <span style="font-size: 12px; color: var(--text-secondary);">${name}</span>
                            <span style="font-size: 12px; font-weight: 600; color: var(--primary-blue);">${formatNumber(count)}</span>
                        </div>
                        <div style="height: 4px; background: var(--light-blue); border-radius: 2px; overflow: hidden;">
                            <div style="height: 100%; background: var(--primary-blue); border-radius: 2px; width: ${(count / maxGeo) * 100}%;"></div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderGeoMapMobile();
}

function renderGeoMap(geoData) {
    const mapContainer = document.getElementById('geoMap');
    if (!mapContainer) return;
    
    let currentChart;
    
    if (currentGeoTab === 'china') {
        if (!geoMapChartChina) {
            geoMapChartChina = echarts.init(mapContainer);
            window.addEventListener('resize', () => {
                if (geoMapChartChina) {
                    geoMapChartChina.resize();
                }
            });
        }
        currentChart = geoMapChartChina;
        
        if (geoMapChartWorld) {
            geoMapChartWorld.clear();
        }
    } else {
        if (!geoMapChartWorld) {
            geoMapChartWorld = echarts.init(mapContainer);
            window.addEventListener('resize', () => {
                if (geoMapChartWorld) {
                    geoMapChartWorld.resize();
                }
            });
        }
        currentChart = geoMapChartWorld;
        
        if (geoMapChartChina) {
            geoMapChartChina.clear();
        }
    }
    
    const provinceNameMap = {
        '北京': '北京市',
        '天津': '天津市',
        '上海': '上海市',
        '重庆': '重庆市',
        '河北': '河北省',
        '山西': '山西省',
        '辽宁': '辽宁省',
        '吉林': '吉林省',
        '黑龙江': '黑龙江省',
        '江苏': '江苏省',
        '浙江': '浙江省',
        '安徽': '安徽省',
        '福建': '福建省',
        '江西': '江西省',
        '山东': '山东省',
        '河南': '河南省',
        '湖北': '湖北省',
        '湖南': '湖南省',
        '广东': '广东省',
        '海南': '海南省',
        '四川': '四川省',
        '贵州': '贵州省',
        '云南': '云南省',
        '陕西': '陕西省',
        '甘肃': '甘肃省',
        '青海': '青海省',
        '台湾': '台湾省',
        '内蒙古': '内蒙古自治区',
        '广西': '广西壮族自治区',
        '西藏': '西藏自治区',
        '宁夏': '宁夏回族自治区',
        '新疆': '新疆维吾尔自治区',
        '香港': '香港特别行政区',
        '澳门': '澳门特别行政区',
        '北京市': '北京市',
        '天津市': '天津市',
        '上海市': '上海市',
        '重庆市': '重庆市',
        '河北省': '河北省',
        '山西省': '山西省',
        '辽宁省': '辽宁省',
        '吉林省': '吉林省',
        '黑龙江省': '黑龙江省',
        '江苏省': '江苏省',
        '浙江省': '浙江省',
        '安徽省': '安徽省',
        '福建省': '福建省',
        '江西省': '江西省',
        '山东省': '山东省',
        '河南省': '河南省',
        '湖北省': '湖北省',
        '湖南省': '湖南省',
        '广东省': '广东省',
        '海南省': '海南省',
        '四川省': '四川省',
        '贵州省': '贵州省',
        '云南省': '云南省',
        '陕西省': '陕西省',
        '甘肃省': '甘肃省',
        '青海省': '青海省',
        '台湾省': '台湾省',
        '内蒙古自治区': '内蒙古自治区',
        '广西壮族自治区': '广西壮族自治区',
        '西藏自治区': '西藏自治区',
        '宁夏回族自治区': '宁夏回族自治区',
        '新疆维吾尔自治区': '新疆维吾尔自治区',
        '香港特别行政区': '香港特别行政区',
        '澳门特别行政区': '澳门特别行政区'
    };
    
    const countryNameMap = {
        '中国': 'China',
        '美国': 'United States',
        '俄罗斯': 'Russia',
        '日本': 'Japan',
        '韩国': 'Korea',
        '朝鲜': 'Dem. Rep. Korea',
        '英国': 'United Kingdom',
        '法国': 'France',
        '德国': 'Germany',
        '意大利': 'Italy',
        '西班牙': 'Spain',
        '巴西': 'Brazil',
        '加拿大': 'Canada',
        '澳大利亚': 'Australia',
        '印度': 'India',
        '印度尼西亚': 'Indonesia',
        '马来西亚': 'Malaysia',
        '新加坡': 'Singapore',
        '泰国': 'Thailand',
        '越南': 'Vietnam',
        '菲律宾': 'Philippines',
        '荷兰': 'Netherlands',
        '比利时': 'Belgium',
        '瑞士': 'Switzerland',
        '瑞典': 'Sweden',
        '挪威': 'Norway',
        '丹麦': 'Denmark',
        '芬兰': 'Finland',
        '波兰': 'Poland',
        '捷克': 'Czech Rep.',
        '罗马尼亚': 'Romania',
        '乌克兰': 'Ukraine',
        '埃及': 'Egypt',
        '南非': 'South Africa',
        '尼日利亚': 'Nigeria',
        '墨西哥': 'Mexico',
        '阿根廷': 'Argentina',
        '智利': 'Chile',
        '哥伦比亚': 'Colombia',
        '秘鲁': 'Peru',
        '新西兰': 'New Zealand',
        '土耳其': 'Turkey',
        '伊朗': 'Iran',
        '以色列': 'Israel',
        '巴基斯坦': 'Pakistan',
        '孟加拉国': 'Bangladesh',
        '哈萨克斯坦': 'Kazakhstan',
        '乌兹别克斯坦': 'Uzbekistan',
        '蒙古': 'Mongolia',
        '老挝': 'Lao PDR',
        '柬埔寨': 'Cambodia',
        '缅甸': 'Myanmar',
        '不丹': 'Bhutan',
        '尼泊尔': 'Nepal',
        '斯里兰卡': 'Sri Lanka',
        '马尔代夫': 'Maldives',
        '文莱': 'Brunei',
        '东帝汶': 'Timor-Leste',
        '巴布亚新几内亚': 'Papua New Guinea',
        '所罗门群岛': 'Solomon Is.',
        '瓦努阿图': 'Vanuatu',
        '斐济': 'Fiji',
        '汤加': 'Tonga',
        '萨摩亚': 'Samoa',
        '基里巴斯': 'Kiribati',
        '图瓦卢': 'Tuvalu',
        '瑙鲁': 'Nauru',
        '帕劳': 'Palau',
        '密克罗尼西亚': 'Micronesia',
        '马绍尔群岛': 'Marshall Islands',
        '爱尔兰': 'Ireland',
        '葡萄牙': 'Portugal',
        '希腊': 'Greece',
        '保加利亚': 'Bulgaria',
        '匈牙利': 'Hungary',
        '奥地利': 'Austria',
        '斯洛伐克': 'Slovakia',
        '克罗地亚': 'Croatia',
        '塞尔维亚': 'Serbia',
        '斯洛文尼亚': 'Slovenia',
        '爱沙尼亚': 'Estonia',
        '拉脱维亚': 'Latvia',
        '立陶宛': 'Lithuania',
        '白俄罗斯': 'Belarus',
        '摩尔多瓦': 'Moldova',
        '阿塞拜疆': 'Azerbaijan',
        '格鲁吉亚': 'Georgia',
        '亚美尼亚': 'Armenia',
        '塔吉克斯坦': 'Tajikistan',
        '吉尔吉斯斯坦': 'Kyrgyzstan',
        '土库曼斯坦': 'Turkmenistan',
        '阿富汗': 'Afghanistan',
        '伊拉克': 'Iraq',
        '叙利亚': 'Syria',
        '约旦': 'Jordan',
        '黎巴嫩': 'Lebanon',
        '塞浦路斯': 'Cyprus',
        '科威特': 'Kuwait',
        '沙特阿拉伯': 'Saudi Arabia',
        '卡塔尔': 'Qatar',
        '阿联酋': 'United Arab Emirates',
        '阿曼': 'Oman',
        '也门': 'Yemen',
        '索马里': 'Somalia',
        '肯尼亚': 'Kenya',
        '埃塞俄比亚': 'Ethiopia',
        '刚果': 'Congo',
        '安哥拉': 'Angola',
        '赞比亚': 'Zambia',
        '莫桑比克': 'Mozambique',
        '博茨瓦纳': 'Botswana',
        '纳米比亚': 'Namibia',
        '津巴布韦': 'Zimbabwe',
        '斯威士兰': 'Swaziland',
        '莱索托': 'Lesotho',
        '马达加斯加': 'Madagascar',
        '毛里求斯': 'Mauritius',
        '塞舌尔': 'Seychelles',
        '科摩罗': 'Comoros',
        '古巴': 'Cuba',
        '多米尼加': 'Dominican Rep.',
        '海地': 'Haiti',
        '牙买加': 'Jamaica',
        '波多黎各': 'Puerto Rico',
        '哥斯达黎加': 'Costa Rica',
        '巴拿马': 'Panama',
        '危地马拉': 'Guatemala',
        '洪都拉斯': 'Honduras',
        '萨尔瓦多': 'El Salvador',
        '尼加拉瓜': 'Nicaragua',
        '巴拉圭': 'Paraguay',
        '乌拉圭': 'Uruguay',
        '玻利维亚': 'Bolivia',
        '厄瓜多尔': 'Ecuador',
        '委内瑞拉': 'Venezuela',
        '圭亚那': 'Guyana',
        '苏里南': 'Suriname',
        '法属圭亚那': 'Fr. Guiana',
        '阿尔巴尼亚': 'Albania',
        '阿尔及利亚': 'Algeria',
        '美属萨摩亚': 'American Samoa',
        '安道尔': 'Andorra',
        '安哥拉': 'Angola',
        '安提瓜和巴布达': 'Antigua and Barb.',
        '巴哈马': 'Bahamas',
        '巴林': 'Bahrain',
        '巴巴多斯': 'Barbados',
        '伯利兹': 'Belize',
        '贝宁': 'Benin',
        '百慕大': 'Bermuda',
        '波斯尼亚和黑塞哥维那': 'Bosnia and Herz.',
        '博茨瓦纳': 'Botswana',
        '英属印度洋领地': 'Br. Indian Ocean Ter.',
        '布基纳法索': 'Burkina Faso',
        '布隆迪': 'Burundi',
        '喀麦隆': 'Cameroon',
        '佛得角': 'Cape Verde',
        '开曼群岛': 'Cayman Is.',
        '中非共和国': 'Central African Rep.',
        '乍得': 'Chad',
        '科摩罗': 'Comoros',
        '哥斯达黎加': 'Costa Rica',
        '克罗地亚': 'Croatia',
        '古巴': 'Cuba',
        '库拉索': 'Curaçao',
        '塞浦路斯': 'Cyprus',
        '捷克共和国': 'Czech Rep.',
        '科特迪瓦': "Côte d'Ivoire",
        '刚果民主共和国': 'Dem. Rep. Congo',
        '吉布提': 'Djibouti',
        '多米尼克': 'Dominica',
        '厄瓜多尔': 'Ecuador',
        '埃及': 'Egypt',
        '萨尔瓦多': 'El Salvador',
        '赤道几内亚': 'Eq. Guinea',
        '厄立特里亚': 'Eritrea',
        '爱沙尼亚': 'Estonia',
        '法罗群岛': 'Faeroe Is.',
        '福克兰群岛': 'Falkland Is.',
        '法属波利尼西亚': 'Fr. Polynesia',
        '法属南部领地': 'Fr. S. Antarctic Lands',
        '加蓬': 'Gabon',
        '冈比亚': 'Gambia',
        '加纳': 'Ghana',
        '希腊': 'Greece',
        '格陵兰': 'Greenland',
        '格林纳达': 'Grenada',
        '关岛': 'Guam',
        '危地马拉': 'Guatemala',
        '几内亚': 'Guinea',
        '几内亚比绍': 'Guinea-Bissau',
        '圭亚那': 'Guyana',
        '海地': 'Haiti',
        '赫德岛和麦克唐纳群岛': 'Heard I. and McDonald Is.',
        '洪都拉斯': 'Honduras',
        '冰岛': 'Iceland',
        '印度': 'India',
        '印度尼西亚': 'Indonesia',
        '伊朗': 'Iran',
        '伊拉克': 'Iraq',
        '爱尔兰': 'Ireland',
        '马恩岛': 'Isle of Man',
        '以色列': 'Israel',
        '意大利': 'Italy',
        '牙买加': 'Jamaica',
        '日本': 'Japan',
        '泽西': 'Jersey',
        '约旦': 'Jordan',
        '哈萨克斯坦': 'Kazakhstan',
        '肯尼亚': 'Kenya',
        '基里巴斯': 'Kiribati',
        '韩国': 'Korea',
        '科威特': 'Kuwait',
        '吉尔吉斯斯坦': 'Kyrgyzstan',
        '老挝': 'Lao PDR',
        '拉脱维亚': 'Latvia',
        '黎巴嫩': 'Lebanon',
        '莱索托': 'Lesotho',
        '利比里亚': 'Liberia',
        '利比亚': 'Libya',
        '列支敦士登': 'Liechtenstein',
        '立陶宛': 'Lithuania',
        '卢森堡': 'Luxembourg',
        '马其顿': 'Macedonia',
        '马达加斯加': 'Madagascar',
        '马拉维': 'Malawi',
        '马来西亚': 'Malaysia',
        '马里': 'Mali',
        '马耳他': 'Malta',
        '毛里塔尼亚': 'Mauritania',
        '毛里求斯': 'Mauritius',
        '墨西哥': 'Mexico',
        '密克罗尼西亚': 'Micronesia',
        '摩尔多瓦': 'Moldova',
        '蒙古': 'Mongolia',
        '黑山': 'Montenegro',
        '蒙特塞拉特': 'Montserrat',
        '摩洛哥': 'Morocco',
        '莫桑比克': 'Mozambique',
        '缅甸': 'Myanmar',
        '北塞浦路斯': 'N. Cyprus',
        '北马里亚纳群岛': 'N. Mariana Is.',
        '纳米比亚': 'Namibia',
        '尼泊尔': 'Nepal',
        '荷兰': 'Netherlands',
        '新喀里多尼亚': 'New Caledonia',
        '新西兰': 'New Zealand',
        '尼加拉瓜': 'Nicaragua',
        '尼日尔': 'Niger',
        '尼日利亚': 'Nigeria',
        '纽埃': 'Niue',
        '挪威': 'Norway',
        '阿曼': 'Oman',
        '巴基斯坦': 'Pakistan',
        '帕劳': 'Palau',
        '巴勒斯坦': 'Palestine',
        '巴拿马': 'Panama',
        '巴布亚新几内亚': 'Papua New Guinea',
        '巴拉圭': 'Paraguay',
        '秘鲁': 'Peru',
        '菲律宾': 'Philippines',
        '波兰': 'Poland',
        '葡萄牙': 'Portugal',
        '波多黎各': 'Puerto Rico',
        '卡塔尔': 'Qatar',
        '罗马尼亚': 'Romania',
        '俄罗斯': 'Russia',
        '卢旺达': 'Rwanda',
        '南乔治亚和南桑威奇群岛': 'S. Geo. and S. Sandw. Is.',
        '南苏丹': 'S. Sudan',
        '圣赫勒拿': 'Saint Helena',
        '圣卢西亚': 'Saint Lucia',
        '萨摩亚': 'Samoa',
        '沙特阿拉伯': 'Saudi Arabia',
        '塞内加尔': 'Senegal',
        '塞尔维亚': 'Serbia',
        '塞舌尔': 'Seychelles',
        '锡亚琴冰川': 'Siachen Glacier',
        '塞拉利昂': 'Sierra Leone',
        '新加坡': 'Singapore',
        '斯洛伐克': 'Slovakia',
        '斯洛文尼亚': 'Slovenia',
        '所罗门群岛': 'Solomon Is.',
        '索马里': 'Somalia',
        '南非': 'South Africa',
        '西班牙': 'Spain',
        '斯里兰卡': 'Sri Lanka',
        '圣皮埃尔和密克隆': 'St. Pierre and Miquelon',
        '圣文森特和格林纳丁斯': 'St. Vin. and Gren.',
        '苏丹': 'Sudan',
        '苏里南': 'Suriname',
        '斯威士兰': 'Swaziland',
        '瑞典': 'Sweden',
        '瑞士': 'Switzerland',
        '叙利亚': 'Syria',
        '圣多美和普林西比': 'São Tomé and Principe',
        '塔吉克斯坦': 'Tajikistan',
        '坦桑尼亚': 'Tanzania',
        '泰国': 'Thailand',
        '东帝汶': 'Timor-Leste',
        '多哥': 'Togo',
        '汤加': 'Tonga',
        '特立尼达和多巴哥': 'Trinidad and Tobago',
        '突尼斯': 'Tunisia',
        '土耳其': 'Turkey',
        '土库曼斯坦': 'Turkmenistan',
        '特克斯和凯科斯群岛': 'Turks and Caicos Is.',
        '美属维尔京群岛': 'U.S. Virgin Is.',
        '乌干达': 'Uganda',
        '乌克兰': 'Ukraine',
        '阿拉伯联合酋长国': 'United Arab Emirates',
        '英国': 'United Kingdom',
        '美国': 'United States',
        '乌拉圭': 'Uruguay',
        '乌兹别克斯坦': 'Uzbekistan',
        '瓦努阿图': 'Vanuatu',
        '委内瑞拉': 'Venezuela',
        '越南': 'Vietnam',
        '西撒哈拉': 'W. Sahara',
        '也门': 'Yemen',
        '赞比亚': 'Zambia',
        '津巴布韦': 'Zimbabwe'
    };
    
    const countryNameMapReverse = {
        'Afghanistan': '阿富汗',
        'Aland': '奥兰群岛',
        'Albania': '阿尔巴尼亚',
        'Algeria': '阿尔及利亚',
        'American Samoa': '美属萨摩亚',
        'Andorra': '安道尔',
        'Angola': '安哥拉',
        'Antigua and Barb.': '安提瓜和巴布达',
        'Argentina': '阿根廷',
        'Armenia': '亚美尼亚',
        'Australia': '澳大利亚',
        'Austria': '奥地利',
        'Azerbaijan': '阿塞拜疆',
        'Bahamas': '巴哈马',
        'Bahrain': '巴林',
        'Bangladesh': '孟加拉国',
        'Barbados': '巴巴多斯',
        'Belarus': '白俄罗斯',
        'Belgium': '比利时',
        'Belize': '伯利兹',
        'Benin': '贝宁',
        'Bermuda': '百慕大',
        'Bhutan': '不丹',
        'Bolivia': '玻利维亚',
        'Bosnia and Herz.': '波斯尼亚和黑塞哥维那',
        'Botswana': '博茨瓦纳',
        'Br. Indian Ocean Ter.': '英属印度洋领地',
        'Brazil': '巴西',
        'Brunei': '文莱',
        'Bulgaria': '保加利亚',
        'Burkina Faso': '布基纳法索',
        'Burundi': '布隆迪',
        'Cambodia': '柬埔寨',
        'Cameroon': '喀麦隆',
        'Canada': '加拿大',
        'Cape Verde': '佛得角',
        'Cayman Is.': '开曼群岛',
        'Central African Rep.': '中非共和国',
        'Chad': '乍得',
        'Chile': '智利',
        'China': '中国',
        'Colombia': '哥伦比亚',
        'Comoros': '科摩罗',
        'Congo': '刚果',
        'Costa Rica': '哥斯达黎加',
        'Croatia': '克罗地亚',
        'Cuba': '古巴',
        'Curaçao': '库拉索',
        'Cyprus': '塞浦路斯',
        'Czech Rep.': '捷克共和国',
        "Côte d'Ivoire": '科特迪瓦',
        'Dem. Rep. Congo': '刚果民主共和国',
        'Dem. Rep. Korea': '朝鲜',
        'Denmark': '丹麦',
        'Djibouti': '吉布提',
        'Dominica': '多米尼克',
        'Dominican Rep.': '多米尼加',
        'Ecuador': '厄瓜多尔',
        'Egypt': '埃及',
        'El Salvador': '萨尔瓦多',
        'Eq. Guinea': '赤道几内亚',
        'Eritrea': '厄立特里亚',
        'Estonia': '爱沙尼亚',
        'Ethiopia': '埃塞俄比亚',
        'Faeroe Is.': '法罗群岛',
        'Falkland Is.': '福克兰群岛',
        'Fiji': '斐济',
        'Finland': '芬兰',
        'Fr. Polynesia': '法属波利尼西亚',
        'Fr. S. Antarctic Lands': '法属南部领地',
        'France': '法国',
        'Gabon': '加蓬',
        'Gambia': '冈比亚',
        'Georgia': '格鲁吉亚',
        'Germany': '德国',
        'Ghana': '加纳',
        'Greece': '希腊',
        'Greenland': '格陵兰',
        'Grenada': '格林纳达',
        'Guam': '关岛',
        'Guatemala': '危地马拉',
        'Guinea': '几内亚',
        'Guinea-Bissau': '几内亚比绍',
        'Guyana': '圭亚那',
        'Haiti': '海地',
        'Heard I. and McDonald Is.': '赫德岛和麦克唐纳群岛',
        'Honduras': '洪都拉斯',
        'Hungary': '匈牙利',
        'Iceland': '冰岛',
        'India': '印度',
        'Indonesia': '印度尼西亚',
        'Iran': '伊朗',
        'Iraq': '伊拉克',
        'Ireland': '爱尔兰',
        'Isle of Man': '马恩岛',
        'Israel': '以色列',
        'Italy': '意大利',
        'Jamaica': '牙买加',
        'Japan': '日本',
        'Jersey': '泽西',
        'Jordan': '约旦',
        'Kazakhstan': '哈萨克斯坦',
        'Kenya': '肯尼亚',
        'Kiribati': '基里巴斯',
        'Korea': '韩国',
        'Kuwait': '科威特',
        'Kyrgyzstan': '吉尔吉斯斯坦',
        'Lao PDR': '老挝',
        'Latvia': '拉脱维亚',
        'Lebanon': '黎巴嫩',
        'Lesotho': '莱索托',
        'Liberia': '利比里亚',
        'Libya': '利比亚',
        'Liechtenstein': '列支敦士登',
        'Lithuania': '立陶宛',
        'Luxembourg': '卢森堡',
        'Macedonia': '马其顿',
        'Madagascar': '马达加斯加',
        'Malawi': '马拉维',
        'Malaysia': '马来西亚',
        'Mali': '马里',
        'Malta': '马耳他',
        'Mauritania': '毛里塔尼亚',
        'Mauritius': '毛里求斯',
        'Mexico': '墨西哥',
        'Micronesia': '密克罗尼西亚',
        'Moldova': '摩尔多瓦',
        'Mongolia': '蒙古',
        'Montenegro': '黑山',
        'Montserrat': '蒙特塞拉特',
        'Morocco': '摩洛哥',
        'Mozambique': '莫桑比克',
        'Myanmar': '缅甸',
        'N. Cyprus': '北塞浦路斯',
        'N. Mariana Is.': '北马里亚纳群岛',
        'Namibia': '纳米比亚',
        'Nepal': '尼泊尔',
        'Netherlands': '荷兰',
        'New Caledonia': '新喀里多尼亚',
        'New Zealand': '新西兰',
        'Nicaragua': '尼加拉瓜',
        'Niger': '尼日尔',
        'Nigeria': '尼日利亚',
        'Niue': '纽埃',
        'Norway': '挪威',
        'Oman': '阿曼',
        'Pakistan': '巴基斯坦',
        'Palau': '帕劳',
        'Palestine': '巴勒斯坦',
        'Panama': '巴拿马',
        'Papua New Guinea': '巴布亚新几内亚',
        'Paraguay': '巴拉圭',
        'Peru': '秘鲁',
        'Philippines': '菲律宾',
        'Poland': '波兰',
        'Portugal': '葡萄牙',
        'Puerto Rico': '波多黎各',
        'Qatar': '卡塔尔',
        'Romania': '罗马尼亚',
        'Russia': '俄罗斯',
        'Rwanda': '卢旺达',
        'S. Geo. and S. Sandw. Is.': '南乔治亚和南桑威奇群岛',
        'S. Sudan': '南苏丹',
        'Saint Helena': '圣赫勒拿',
        'Saint Lucia': '圣卢西亚',
        'Samoa': '萨摩亚',
        'Saudi Arabia': '沙特阿拉伯',
        'Senegal': '塞内加尔',
        'Serbia': '塞尔维亚',
        'Seychelles': '塞舌尔',
        'Siachen Glacier': '锡亚琴冰川',
        'Sierra Leone': '塞拉利昂',
        'Singapore': '新加坡',
        'Slovakia': '斯洛伐克',
        'Slovenia': '斯洛文尼亚',
        'Solomon Is.': '所罗门群岛',
        'Somalia': '索马里',
        'South Africa': '南非',
        'Spain': '西班牙',
        'Sri Lanka': '斯里兰卡',
        'St. Pierre and Miquelon': '圣皮埃尔和密克隆',
        'St. Vin. and Gren.': '圣文森特和格林纳丁斯',
        'Sudan': '苏丹',
        'Suriname': '苏里南',
        'Swaziland': '斯威士兰',
        'Sweden': '瑞典',
        'Switzerland': '瑞士',
        'Syria': '叙利亚',
        'São Tomé and Principe': '圣多美和普林西比',
        'Tajikistan': '塔吉克斯坦',
        'Tanzania': '坦桑尼亚',
        'Thailand': '泰国',
        'Timor-Leste': '东帝汶',
        'Togo': '多哥',
        'Tonga': '汤加',
        'Trinidad and Tobago': '特立尼达和多巴哥',
        'Tunisia': '突尼斯',
        'Turkey': '土耳其',
        'Turkmenistan': '土库曼斯坦',
        'Turks and Caicos Is.': '特克斯和凯科斯群岛',
        'U.S. Virgin Is.': '美属维尔京群岛',
        'Uganda': '乌干达',
        'Ukraine': '乌克兰',
        'United Arab Emirates': '阿拉伯联合酋长国',
        'United Kingdom': '英国',
        'United States': '美国',
        'Uruguay': '乌拉圭',
        'Uzbekistan': '乌兹别克斯坦',
        'Vanuatu': '瓦努阿图',
        'Venezuela': '委内瑞拉',
        'Vietnam': '越南',
        'W. Sahara': '西撒哈拉',
        'Yemen': '也门',
        'Zambia': '赞比亚',
        'Zimbabwe': '津巴布韦'
    };
    
    const convertData = () => {
        return Object.entries(geoData).map(([name, value]) => {
            let mappedName = name;
            if (currentGeoTab === 'china') {
                mappedName = provinceNameMap[name] || name;
            } else {
                mappedName = countryNameMap[name] || name;
            }
            return {
                name: mappedName,
                value: value
            };
        });
    };
    
    let option;
    
    if (currentGeoTab === 'china') {
        option = {
            backgroundColor: '#ffffff',
            tooltip: {
                trigger: 'item',
                backgroundColor: 'rgba(255,255,255,0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                },
                formatter: function(params) {
                    let actionText = '';
                    if (currentActionTab === 'access') {
                        actionText = '访问';
                    } else if (currentActionTab === 'detected') {
                        actionText = '未拦截';
                    } else if (currentActionTab === 'blocked') {
                        actionText = '已拦截';
                    }
                    let value = 0;
                    if (params.value && params.value !== 'NaN') {
                        value = params.value;
                    }
                    let displayName = params.name;
                    if (currentGeoTab === 'world' && countryNameMapReverse[params.name]) {
                        displayName = countryNameMapReverse[params.name];
                    }
                    return displayName + '<br/>' + actionText + ': ' + value;
                }
            },
            visualMap: {
                min: 0,
                max: Math.max(...Object.values(geoData), 1),
                left: 10,
                bottom: 10,
                text: ['高', '低'],
                textStyle: {
                    color: '#5f6368',
                    fontSize: 10
                },
                calculable: false,
                inRange: {
                    color: ['#e3f2fd', '#bbdefb', '#90caf9', '#64b5f6', '#42a5f5', '#2196f3', '#1e88e5', '#1976d2', '#1565c0', '#0d47a1']
                }
            },
            series: [
                {
                    name: '地理位置分布',
                    type: 'map',
                    map: 'china',
                    roam: false,
                    label: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            color: '#202124',
                            fontSize: 10
                        },
                        itemStyle: {
                            areaColor: '#ff9800'
                        }
                    },
                    itemStyle: {
                        areaColor: '#f5f7fa',
                        borderColor: '#dadce0',
                        borderWidth: 1
                    },
                    data: convertData(),
                    zoom: 1.5,
                    center: [105, 36]
                }
            ]
        };
        
        fetch('/static/maps/china.json')
            .then(response => response.json())
            .then(chinaJson => {
                echarts.registerMap('china', chinaJson);
                currentChart.setOption(option);
            })
            .catch(error => {
                console.error('加载中国地图数据失败:', error);
                renderSimpleMap(convertData(), 'china');
            });
    } else {
        option = {
            backgroundColor: '#ffffff',
            tooltip: {
                trigger: 'item',
                backgroundColor: 'rgba(255,255,255,0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                },
                formatter: function(params) {
                    let actionText = '';
                    if (currentActionTab === 'access') {
                        actionText = '访问';
                    } else if (currentActionTab === 'detected') {
                        actionText = '未拦截';
                    } else if (currentActionTab === 'blocked') {
                        actionText = '已拦截';
                    }
                    let value = 0;
                    if (params.value && params.value !== 'NaN') {
                        value = params.value;
                    }
                    let displayName = params.name;
                    if (currentGeoTab === 'world' && countryNameMapReverse[params.name]) {
                        displayName = countryNameMapReverse[params.name];
                    }
                    return displayName + '<br/>' + actionText + ': ' + value;
                }
            },
            visualMap: {
                min: 0,
                max: Math.max(...Object.values(geoData), 1),
                left: 10,
                bottom: 10,
                text: ['高', '低'],
                textStyle: {
                    color: '#5f6368',
                    fontSize: 10
                },
                calculable: false,
                inRange: {
                    color: ['#e3f2fd', '#bbdefb', '#90caf9', '#64b5f6', '#42a5f5', '#2196f3', '#1e88e5', '#1976d2', '#1565c0', '#0d47a1']
                }
            },
            series: [
                {
                    name: '地理位置分布',
                    type: 'map',
                    map: 'world',
                    roam: false,
                    label: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            color: '#202124',
                            fontSize: 8
                        },
                        itemStyle: {
                            areaColor: '#ff9800'
                        }
                    },
                    itemStyle: {
                        areaColor: '#f5f7fa',
                        borderColor: '#dadce0',
                        borderWidth: 0.5
                    },
                    data: convertData()
                }
            ]
        };
        
        fetch('/static/maps/world.json')
            .then(response => response.json())
            .then(worldJson => {
                echarts.registerMap('world', worldJson);
                currentChart.setOption(option);
            })
            .catch(error => {
                console.error('加载世界地图数据失败:', error);
                renderSimpleMap(convertData(), 'world');
            });
    }
}

function renderGeoMapMobile() {
    const mapContainer = document.getElementById('geoMap-mobile');
    if (!mapContainer) return;

    let geoData = {};

    if (currentActionTab === 'access') {
        if (currentGeoTab === 'china') {
            geoData = statsData.accessProvinceDistribution || {};
        } else {
            geoData = statsData.accessGeoDistribution || {};
        }
    } else if (currentActionTab === 'detected') {
        if (currentGeoTab === 'china') {
            geoData = statsData.detectedProvinceDistribution || {};
        } else {
            geoData = statsData.detectedGeoDistribution || {};
        }
    } else if (currentActionTab === 'blocked') {
        if (currentGeoTab === 'china') {
            geoData = statsData.blockedProvinceDistribution || {};
        } else {
            geoData = statsData.blockedGeoDistribution || {};
        }
    }

    let currentChart;

    if (currentGeoTab === 'china') {
        if (!window.geoMapChartChinaMobile) {
            window.geoMapChartChinaMobile = echarts.init(mapContainer);
            window.addEventListener('resize', () => {
                if (window.geoMapChartChinaMobile) {
                    window.geoMapChartChinaMobile.resize();
                }
            });
        }
        currentChart = window.geoMapChartChinaMobile;

        if (window.geoMapChartWorldMobile) {
            window.geoMapChartWorldMobile.clear();
        }
    } else {
        if (!window.geoMapChartWorldMobile) {
            window.geoMapChartWorldMobile = echarts.init(mapContainer);
            window.addEventListener('resize', () => {
                if (window.geoMapChartWorldMobile) {
                    window.geoMapChartWorldMobile.resize();
                }
            });
        }
        currentChart = window.geoMapChartWorldMobile;

        if (window.geoMapChartChinaMobile) {
            window.geoMapChartChinaMobile.clear();
        }
    }

    const provinceNameMap = {
        '北京': '北京市',
        '天津': '天津市',
        '上海': '上海市',
        '重庆': '重庆市',
        '河北': '河北省',
        '山西': '山西省',
        '辽宁': '辽宁省',
        '吉林': '吉林省',
        '黑龙江': '黑龙江省',
        '江苏': '江苏省',
        '浙江': '浙江省',
        '安徽': '安徽省',
        '福建': '福建省',
        '江西': '江西省',
        '山东': '山东省',
        '河南': '河南省',
        '湖北': '湖北省',
        '湖南': '湖南省',
        '广东': '广东省',
        '海南': '海南省',
        '四川': '四川省',
        '贵州': '贵州省',
        '云南': '云南省',
        '陕西': '陕西省',
        '甘肃': '甘肃省',
        '青海': '青海省',
        '台湾': '台湾省',
        '内蒙古': '内蒙古自治区',
        '广西': '广西壮族自治区',
        '西藏': '西藏自治区',
        '宁夏': '宁夏回族自治区',
        '新疆': '新疆维吾尔自治区',
        '香港': '香港特别行政区',
        '澳门': '澳门特别行政区',
        '北京市': '北京市',
        '天津市': '天津市',
        '上海市': '上海市',
        '重庆市': '重庆市',
        '河北省': '河北省',
        '山西省': '山西省',
        '辽宁省': '辽宁省',
        '吉林省': '吉林省',
        '黑龙江省': '黑龙江省',
        '江苏省': '江苏省',
        '浙江省': '浙江省',
        '安徽省': '安徽省',
        '福建省': '福建省',
        '江西省': '江西省',
        '山东省': '山东省',
        '河南省': '河南省',
        '湖北省': '湖北省',
        '湖南省': '湖南省',
        '广东省': '广东省',
        '海南省': '海南省',
        '四川省': '四川省',
        '贵州省': '贵州省',
        '云南省': '云南省',
        '陕西省': '陕西省',
        '甘肃省': '甘肃省',
        '青海省': '青海省',
        '台湾省': '台湾省',
        '内蒙古自治区': '内蒙古自治区',
        '广西壮族自治区': '广西壮族自治区',
        '西藏自治区': '西藏自治区',
        '宁夏回族自治区': '宁夏回族自治区',
        '新疆维吾尔自治区': '新疆维吾尔自治区',
        '香港特别行政区': '香港特别行政区',
        '澳门特别行政区': '澳门特别行政区'
    };

    const countryNameMap = {
        '中国': 'China',
        '美国': 'United States',
        '俄罗斯': 'Russia',
        '日本': 'Japan',
        '韩国': 'Korea',
        '英国': 'United Kingdom',
        '法国': 'France',
        '德国': 'Germany',
        '意大利': 'Italy',
        '西班牙': 'Spain',
        '巴西': 'Brazil',
        '加拿大': 'Canada',
        '澳大利亚': 'Australia',
        '印度': 'India',
        '印度尼西亚': 'Indonesia',
        '马来西亚': 'Malaysia',
        '新加坡': 'Singapore',
        '泰国': 'Thailand',
        '越南': 'Vietnam',
        '菲律宾': 'Philippines',
        '荷兰': 'Netherlands',
        '巴基斯坦': 'Pakistan',
        '俄罗斯': 'Russia',
        '乌克兰': 'Ukraine',
        '波兰': 'Poland',
        '土耳其': 'Turkey',
        '伊朗': 'Iran',
        '伊拉克': 'Iraq',
        '沙特阿拉伯': 'Saudi Arabia',
        '阿联酋': 'United Arab Emirates',
        '尼日利亚': 'Nigeria',
        '埃及': 'Egypt',
        '南非': 'South Africa',
        '墨西哥': 'Mexico',
        '阿根廷': 'Argentina',
        '哥伦比亚': 'Colombia',
        '秘鲁': 'Peru',
        '智利': 'Chile',
        '委内瑞拉': 'Venezuela'
    };

    const countryNameMapReverse = {
        'China': '中国',
        'United States': '美国',
        'Russia': '俄罗斯',
        'Japan': '日本',
        'Korea': '韩国',
        'United Kingdom': '英国',
        'France': '法国',
        'Germany': '德国',
        'Italy': '意大利',
        'Spain': '西班牙',
        'Brazil': '巴西',
        'Canada': '加拿大',
        'Australia': '澳大利亚',
        'India': '印度',
        'Indonesia': '印度尼西亚',
        'Malaysia': '马来西亚',
        'Singapore': '新加坡',
        'Thailand': '泰国',
        'Vietnam': '越南',
        'Philippines': '菲律宾',
        'Netherlands': '荷兰',
        'Pakistan': '巴基斯坦',
        'Ukraine': '乌克兰',
        'Poland': '波兰',
        'Turkey': '土耳其',
        'Iran': '伊朗',
        'Iraq': '伊拉克',
        'Saudi Arabia': '沙特阿拉伯',
        'United Arab Emirates': '阿联酋',
        'Nigeria': '尼日利亚',
        'Egypt': '埃及',
        'South Africa': '南非',
        'Mexico': '墨西哥',
        'Argentina': '阿根廷',
        'Colombia': '哥伦比亚',
        'Peru': '秘鲁',
        'Chile': '智利',
        'Venezuela': '委内瑞拉'
    };

    const convertData = () => {
        return Object.entries(geoData).map(([name, value]) => {
            let mappedName = name;
            if (currentGeoTab === 'china') {
                mappedName = provinceNameMap[name] || name;
            } else {
                mappedName = countryNameMap[name] || name;
            }
            return {
                name: mappedName,
                value: value
            };
        });
    };

    let option;

    if (currentGeoTab === 'china') {
        option = {
            backgroundColor: '#ffffff',
            tooltip: {
                trigger: 'item',
                backgroundColor: 'rgba(255,255,255,0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                },
                formatter: function(params) {
                    let actionText = '';
                    if (currentActionTab === 'access') {
                        actionText = '访问';
                    } else if (currentActionTab === 'detected') {
                        actionText = '未拦截';
                    } else if (currentActionTab === 'blocked') {
                        actionText = '已拦截';
                    }
                    let value = 0;
                    if (params.value && params.value !== 'NaN') {
                        value = params.value;
                    }
                    return params.name + '<br/>' + actionText + ': ' + value;
                }
            },
            visualMap: {
                min: 0,
                max: Math.max(...Object.values(geoData), 1),
                left: 10,
                bottom: 10,
                text: ['高', '低'],
                textStyle: {
                    color: '#5f6368',
                    fontSize: 10
                },
                calculable: false,
                inRange: {
                    color: ['#e3f2fd', '#bbdefb', '#90caf9', '#64b5f6', '#42a5f5', '#2196f3', '#1e88e5', '#1976d2', '#1565c0', '#0d47a1']
                }
            },
            series: [
                {
                    name: '地理位置分布',
                    type: 'map',
                    map: 'china',
                    roam: false,
                    label: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            color: '#202124',
                            fontSize: 8
                        },
                        itemStyle: {
                            areaColor: '#ff9800'
                        }
                    },
                    itemStyle: {
                        areaColor: '#f5f7fa',
                        borderColor: '#dadce0',
                        borderWidth: 0.5
                    },
                    data: convertData()
                }
            ]
        };

        fetch('/static/maps/china.json')
            .then(response => response.json())
            .then(chinaJson => {
                echarts.registerMap('china', chinaJson);
                currentChart.setOption(option);
            })
            .catch(error => {
                console.error('加载中国地图数据失败:', error);
                renderSimpleMapMobile(convertData(), 'china');
            });
    } else {
        option = {
            backgroundColor: '#ffffff',
            tooltip: {
                trigger: 'item',
                backgroundColor: 'rgba(255,255,255,0.95)',
                borderColor: '#e8eaed',
                borderWidth: 1,
                padding: [8, 12],
                textStyle: {
                    color: '#202124',
                    fontSize: 12
                },
                formatter: function(params) {
                    let actionText = '';
                    if (currentActionTab === 'access') {
                        actionText = '访问';
                    } else if (currentActionTab === 'detected') {
                        actionText = '未拦截';
                    } else if (currentActionTab === 'blocked') {
                        actionText = '已拦截';
                    }
                    let value = 0;
                    if (params.value && params.value !== 'NaN') {
                        value = params.value;
                    }
                    let displayName = params.name;
                    if (countryNameMapReverse[params.name]) {
                        displayName = countryNameMapReverse[params.name];
                    }
                    return displayName + '<br/>' + actionText + ': ' + value;
                }
            },
            visualMap: {
                min: 0,
                max: Math.max(...Object.values(geoData), 1),
                left: 10,
                bottom: 10,
                text: ['高', '低'],
                textStyle: {
                    color: '#5f6368',
                    fontSize: 10
                },
                calculable: false,
                inRange: {
                    color: ['#e3f2fd', '#bbdefb', '#90caf9', '#64b5f6', '#42a5f5', '#2196f3', '#1e88e5', '#1976d2', '#1565c0', '#0d47a1']
                }
            },
            series: [
                {
                    name: '地理位置分布',
                    type: 'map',
                    map: 'world',
                    roam: false,
                    label: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            color: '#202124',
                            fontSize: 8
                        },
                        itemStyle: {
                            areaColor: '#ff9800'
                        }
                    },
                    itemStyle: {
                        areaColor: '#f5f7fa',
                        borderColor: '#dadce0',
                        borderWidth: 0.5
                    },
                    data: convertData()
                }
            ]
        };

        fetch('/static/maps/world.json')
            .then(response => response.json())
            .then(worldJson => {
                echarts.registerMap('world', worldJson);
                currentChart.setOption(option);
            })
            .catch(error => {
                console.error('加载世界地图数据失败:', error);
                renderSimpleMapMobile(convertData(), 'world');
            });
    }
}

function renderSimpleMapMobile(data, type) {
    const mapContainer = document.getElementById('geoMap-mobile');
    if (!mapContainer) return;

    let currentChart;
    if (type === 'china') {
        if (!window.geoMapChartChinaMobile) {
            window.geoMapChartChinaMobile = echarts.init(mapContainer);
        }
        currentChart = window.geoMapChartChinaMobile;
    } else {
        if (!window.geoMapChartWorldMobile) {
            window.geoMapChartWorldMobile = echarts.init(mapContainer);
        }
        currentChart = window.geoMapChartWorldMobile;
    }

    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'shadow'
            }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'value',
            axisLabel: {
                fontSize: 10
            }
        },
        yAxis: {
            type: 'category',
            data: data.map(d => d.name).slice(0, 10),
            axisLabel: {
                fontSize: 10
            }
        },
        series: [
            {
                type: 'bar',
                data: data.map(d => d.value).slice(0, 10),
                itemStyle: {
                    color: '#1a73e8'
                },
                label: {
                    show: true,
                    position: 'right',
                    fontSize: 10,
                    formatter: '{c}'
                }
            }
        ]
    };

    currentChart.setOption(option, true);
}

function renderSimpleMap(data, type) {
    const mapContainer = document.getElementById('geoMap');
    if (!mapContainer) return;
    
    let currentChart;
    if (type === 'china') {
        if (!geoMapChartChina) {
            geoMapChartChina = echarts.init(mapContainer);
        }
        currentChart = geoMapChartChina;
    } else {
        if (!geoMapChartWorld) {
            geoMapChartWorld = echarts.init(mapContainer);
        }
        currentChart = geoMapChartWorld;
    }
    
    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'shadow'
            }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'value',
            axisLabel: {
                fontSize: 10
            }
        },
        yAxis: {
            type: 'category',
            data: data.slice(0, 10).map(item => item.name).reverse(),
            axisLabel: {
                fontSize: 10
            }
        },
        series: [
            {
                name: '数量',
                type: 'bar',
                data: data.slice(0, 10).map(item => item.value).reverse(),
                itemStyle: {
                    color: function(params) {
                        const colorList = ['#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de', '#3ba272', '#fc8452', '#9a60b4', '#ea7ccc', '#6b7280'];
                        return colorList[params.dataIndex % colorList.length];
                    }
                }
            }
        ]
    };
    
    currentChart.setOption(option);
}

function switchGeoTab(tab) {
    if (tab === 'access' || tab === 'detected' || tab === 'blocked') {
        currentActionTab = tab;
        document.getElementById('geoTabAccess').classList.toggle('active', tab === 'access');
        document.getElementById('geoTabDetected').classList.toggle('active', tab === 'detected');
        document.getElementById('geoTabBlocked').classList.toggle('active', tab === 'blocked');

        document.getElementById('geoTabAccess-mobile')?.classList.toggle('active', tab === 'access');
        document.getElementById('geoTabDetected-mobile')?.classList.toggle('active', tab === 'detected');
        document.getElementById('geoTabBlocked-mobile')?.classList.toggle('active', tab === 'blocked');

        updateSlider('actionTabContainer', 'actionTabSlider', tab === 'access' ? 'geoTabAccess' : tab === 'detected' ? 'geoTabDetected' : 'geoTabBlocked');
        updateSlider('actionTabContainer-mobile', 'actionTabSlider-mobile', tab === 'access' ? 'geoTabAccess-mobile' : tab === 'detected' ? 'geoTabDetected-mobile' : 'geoTabBlocked-mobile');
    } else {
        currentGeoTab = tab;
        document.getElementById('geoTabWorld').classList.toggle('active', tab === 'world');
        document.getElementById('geoTabChina').classList.toggle('active', tab === 'china');

        document.getElementById('geoTabWorld-mobile')?.classList.toggle('active', tab === 'world');
        document.getElementById('geoTabChina-mobile')?.classList.toggle('active', tab === 'china');

        updateSlider('geoTabContainer', 'geoTabSlider', tab === 'world' ? 'geoTabWorld' : 'geoTabChina');
        updateSlider('geoTabContainer-mobile', 'geoTabSlider-mobile', tab === 'world' ? 'geoTabWorld-mobile' : 'geoTabChina-mobile');
    }
    renderGeoDistribution();
    renderGeoDistributionMobile();
    renderGeoMapMobile();
}

function updateSlider(containerId, sliderId, activeButtonId) {
    const container = document.getElementById(containerId);
    const slider = document.getElementById(sliderId);
    const activeButton = document.getElementById(activeButtonId);

    if (!container || !slider || !activeButton) return;

    const containerRect = container.getBoundingClientRect();
    const buttonRect = activeButton.getBoundingClientRect();

    if (containerRect.width === 0 || buttonRect.width === 0) return;

    const left = buttonRect.left - containerRect.left;
    const width = buttonRect.width;

    slider.style.left = left + 'px';
    slider.style.width = width + 'px';
}

function formatNumber(num) {
    if (num >= 10000) {
        return (num / 1000).toFixed(1) + 'k';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'k';
    }
    return num.toString();
}

document.addEventListener('DOMContentLoaded', async () => {
    const prevDayRadio = document.querySelector('input[name="compare"][value="prev-day"]');
    if (prevDayRadio) prevDayRadio.checked = true;
    
    loadCurrentUser();
    loadSystemSettings();
    loadAvailableRules();
    await loadWAFInstances();
    loadProxyInstances();
    loadCertificates();
    loadPortForwardInstances();
    loadLogs();
    loadStats();
    bindTrendEvents();
    
    setTimeout(() => {
        updateSlider('actionTabContainer', 'actionTabSlider', 'geoTabAccess');
        updateSlider('geoTabContainer', 'geoTabSlider', 'geoTabWorld');
        updateSlider('actionTabContainer-mobile', 'actionTabSlider-mobile', 'geoTabAccess-mobile');
        updateSlider('geoTabContainer-mobile', 'geoTabSlider-mobile', 'geoTabWorld-mobile');
    }, 100);
    
    window.addEventListener('resize', () => {
        const actionTabId = currentActionTab === 'access' ? 'geoTabAccess' : currentActionTab === 'detected' ? 'geoTabDetected' : 'geoTabBlocked';
        const geoTabId = currentGeoTab === 'world' ? 'geoTabWorld' : 'geoTabChina';
        updateSlider('actionTabContainer', 'actionTabSlider', actionTabId);
        updateSlider('geoTabContainer', 'geoTabSlider', geoTabId);
        updateSlider('actionTabContainer-mobile', 'actionTabSlider-mobile', currentActionTab === 'access' ? 'geoTabAccess-mobile' : currentActionTab === 'detected' ? 'geoTabDetected-mobile' : 'geoTabBlocked-mobile');
        updateSlider('geoTabContainer-mobile', 'geoTabSlider-mobile', currentGeoTab === 'world' ? 'geoTabWorld-mobile' : 'geoTabChina-mobile');
        if (geoMapChartWorld) geoMapChartWorld.resize();
        if (geoMapChartChina) geoMapChartChina.resize();
        if (window.geoMapChartWorldMobile) window.geoMapChartWorldMobile.resize();
        if (window.geoMapChartChinaMobile) window.geoMapChartChinaMobile.resize();
    });
    
    setInterval(() => {
        const activeTab = document.querySelector('.tab-content.active');
        if (activeTab && activeTab.id === 'logs-tab') {
            loadLogs();
        }
        loadStats();
    }, 3000);
});
