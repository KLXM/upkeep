/**
 * Dashboard JavaScript für das Upkeep AddOn
 * Vanilla JS mit REDAXO-Kompatibilität
 */

(function() {
    'use strict';
    
    const Dashboard = {
        config: {
            autoRefreshInterval: 30000, // 30 Sekunden
            endpoints: {
                liveStats: 'index.php?page=upkeep/dashboard&func=live_stats',
                recentActivities: 'index.php?page=upkeep/dashboard&func=recent_activities'
            }
        },
        
        state: {
            autoRefreshActive: false,
            intervalId: null
        },
        
        elements: {},
        
        init() {
            this.cacheElements();
            this.bindEvents();
            this.updateLiveTime();
            this.loadRecentActivities();
            this.startLiveTimeUpdate();
            
            // Auto-start refresh wenn gewünscht
            if (localStorage.getItem('upkeep_dashboard_autorefresh') === 'true') {
                this.startAutoRefresh();
            }
        },
        
        cacheElements() {
            this.elements = {
                liveTime: document.getElementById('live-time'),
                autoRefreshBtn: document.getElementById('auto-refresh'),
                refreshActivitiesBtn: document.getElementById('refresh-activities'),
                recentActivities: document.getElementById('recent-activities'),
                blockedIpsCount: document.getElementById('blocked-ips-count'),
                threatsToday: document.getElementById('threats-today-count'),
                allowedIpsCount: document.getElementById('allowed-ips-count'),
                statusCards: document.querySelectorAll('.status-card')
            };
        },
        
        bindEvents() {
            // Auto-Refresh Toggle
            if (this.elements.autoRefreshBtn) {
                this.elements.autoRefreshBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.toggleAutoRefresh();
                });
            }
            
            // Manual Activity Refresh
            if (this.elements.refreshActivitiesBtn) {
                this.elements.refreshActivitiesBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.loadRecentActivities();
                });
            }
            
            // Keyboard Shortcuts
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey || e.metaKey) {
                    switch(e.key) {
                        case 'r':
                            e.preventDefault();
                            this.refreshAll();
                            break;
                        case 'l':
                            e.preventDefault();
                            this.toggleAutoRefresh();
                            break;
                    }
                }
            });
            
            // Visibility API für Pause bei inaktivem Tab
            document.addEventListener('visibilitychange', () => {
                if (document.hidden && this.state.autoRefreshActive) {
                    this.pauseAutoRefresh();
                } else if (!document.hidden && this.state.autoRefreshActive) {
                    this.resumeAutoRefresh();
                }
            });
        },
        
        updateLiveTime() {
            if (!this.elements.liveTime) return;
            
            const now = new Date();
            const timeString = now.toLocaleTimeString('de-DE', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            this.elements.liveTime.textContent = timeString;
        },
        
        startLiveTimeUpdate() {
            // Update time every second
            setInterval(() => {
                this.updateLiveTime();
            }, 1000);
        },
        
        async loadRecentActivities() {
            if (!this.elements.recentActivities) return;
            
            this.showLoading(this.elements.recentActivities);
            
            try {
                const response = await this.fetchWithTimeout(this.config.endpoints.recentActivities);
                
                if (response.ok) {
                    const html = await response.text();
                    this.elements.recentActivities.innerHTML = html;
                    this.animateUpdate(this.elements.recentActivities);
                } else {
                    throw new Error(`HTTP ${response.status}`);
                }
            } catch (error) {
                console.error('Error loading activities:', error);
                this.showError(this.elements.recentActivities, 'Fehler beim Laden der Aktivitäten');
            }
        },
        
        async refreshStats() {
            try {
                const response = await this.fetchWithTimeout(this.config.endpoints.liveStats);
                
                if (response.ok) {
                    const data = await response.json();
                    this.updateStats(data);
                } else {
                    throw new Error(`HTTP ${response.status}`);
                }
            } catch (error) {
                console.error('Error refreshing stats:', error);
                this.showNotification('Fehler beim Aktualisieren der Statistiken', 'error');
            }
        },
        
        updateStats(data) {
            // Update counters with animation
            if (this.elements.blockedIpsCount && data.blocked_ips !== undefined) {
                this.animateCounter(this.elements.blockedIpsCount, data.blocked_ips);
            }
            
            if (this.elements.threatsToday && data.threats_today !== undefined) {
                this.animateCounter(this.elements.threatsToday, data.threats_today);
            }
            
            if (this.elements.allowedIpsCount && data.allowed_ips !== undefined) {
                this.animateCounter(this.elements.allowedIpsCount, data.allowed_ips);
            }
            
            // Animate status cards
            this.elements.statusCards.forEach(card => {
                card.classList.add('updated');
                setTimeout(() => card.classList.remove('updated'), 600);
            });
        },
        
        animateCounter(element, newValue) {
            const currentValue = parseInt(element.textContent) || 0;
            
            if (currentValue === newValue) return;
            
            const duration = 800;
            const steps = 20;
            const stepValue = (newValue - currentValue) / steps;
            const stepDuration = duration / steps;
            
            let step = 0;
            const timer = setInterval(() => {
                step++;
                const value = Math.round(currentValue + (stepValue * step));
                element.textContent = step === steps ? newValue : value;
                
                if (step === steps) {
                    clearInterval(timer);
                }
            }, stepDuration);
        },
        
        toggleAutoRefresh() {
            if (this.state.autoRefreshActive) {
                this.stopAutoRefresh();
            } else {
                this.startAutoRefresh();
            }
        },
        
        startAutoRefresh() {
            this.state.autoRefreshActive = true;
            localStorage.setItem('upkeep_dashboard_autorefresh', 'true');
            
            this.state.intervalId = setInterval(() => {
                this.refreshAll();
            }, this.config.autoRefreshInterval);
            
            this.updateAutoRefreshButton();
            this.showNotification('Auto-Refresh aktiviert', 'success');
        },
        
        stopAutoRefresh() {
            this.state.autoRefreshActive = false;
            localStorage.setItem('upkeep_dashboard_autorefresh', 'false');
            
            if (this.state.intervalId) {
                clearInterval(this.state.intervalId);
                this.state.intervalId = null;
            }
            
            this.updateAutoRefreshButton();
            this.showNotification('Auto-Refresh deaktiviert', 'info');
        },
        
        pauseAutoRefresh() {
            if (this.state.intervalId) {
                clearInterval(this.state.intervalId);
                this.state.intervalId = null;
            }
        },
        
        resumeAutoRefresh() {
            if (this.state.autoRefreshActive && !this.state.intervalId) {
                this.state.intervalId = setInterval(() => {
                    this.refreshAll();
                }, this.config.autoRefreshInterval);
            }
        },
        
        updateAutoRefreshButton() {
            if (!this.elements.autoRefreshBtn) return;
            
            const btn = this.elements.autoRefreshBtn;
            
            if (this.state.autoRefreshActive) {
                btn.className = 'btn btn-xs btn-success active';
                btn.innerHTML = '<i class="rex-icon fa-pause"></i> Stop';
                btn.setAttribute('title', 'Auto-Refresh stoppen (Strg+L)');
            } else {
                btn.className = 'btn btn-xs btn-default';
                btn.innerHTML = '<i class="rex-icon fa-refresh"></i> Live';
                btn.setAttribute('title', 'Auto-Refresh starten (Strg+L)');
            }
        },
        
        refreshAll() {
            this.updateLiveTime();
            this.refreshStats();
            this.loadRecentActivities();
        },
        
        async fetchWithTimeout(url, options = {}, timeout = 10000) {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), timeout);
            
            const defaultOptions = {
                signal: controller.signal,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            };
            
            // Merge options
            const finalOptions = {
                ...defaultOptions,
                ...options,
                headers: {
                    ...defaultOptions.headers,
                    ...options.headers
                }
            };
            
            try {
                const response = await fetch(url, finalOptions);
                clearTimeout(id);
                return response;
            } catch (error) {
                clearTimeout(id);
                throw error;
            }
        },
        
        showLoading(element) {
            element.innerHTML = `
                <div class="text-center" style="padding: 40px;">
                    <div class="spinner"></div>
                    <p style="margin-top: 15px; color: var(--upkeep-text-secondary);">Lädt...</p>
                </div>
            `;
        },
        
        showError(element, message) {
            element.innerHTML = `
                <div class="alert alert-warning">
                    <i class="rex-icon fa-exclamation-triangle"></i> 
                    ${message}
                </div>
            `;
        },
        
        animateUpdate(element) {
            element.style.opacity = '0.7';
            element.style.transform = 'scale(0.98)';
            
            setTimeout(() => {
                element.style.opacity = '1';
                element.style.transform = 'scale(1)';
                element.style.transition = 'all 0.3s ease';
            }, 100);
            
            setTimeout(() => {
                element.style.transition = '';
            }, 400);
        },
        
        showNotification(message, type = 'info') {
            // Verwende REDAXO's Notification System falls verfügbar
            if (typeof rex !== 'undefined' && rex.notification) {
                rex.notification.show(message, type);
                return;
            }
            
            // Fallback: Simple Console Log
            console.log(`Dashboard: ${message}`);
            
            // Einfache visuelle Feedback
            const notification = document.createElement('div');
            notification.className = `alert alert-${type} dashboard-notification`;
            notification.innerHTML = `<i class="rex-icon fa-info-circle"></i> ${message}`;
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                min-width: 300px;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
            `;
            
            document.body.appendChild(notification);
            
            // Animate in
            setTimeout(() => {
                notification.style.opacity = '1';
                notification.style.transform = 'translateX(0)';
            }, 100);
            
            // Auto-remove
            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 3000);
        }
    };
    
    // Initialize Dashboard when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => Dashboard.init());
    } else {
        Dashboard.init();
    }
    
    // REDAXO rex:ready compatibility
    if (typeof jQuery !== 'undefined') {
        jQuery(document).on('rex:ready', () => Dashboard.init());
    }
    
    // Global access for debugging
    window.UpkeepDashboard = Dashboard;
    
})();
