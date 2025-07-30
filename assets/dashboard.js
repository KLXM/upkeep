/**
 * Dashboard JavaScript für das Upkeep AddOn
 * REDAXO-kompatibel mit jQuery und rex:ready
 */

// Warten auf rex:ready Event
jQuery(document).on('rex:ready', function($) {
    'use strict';
    
    console.log('Dashboard: rex:ready event fired');
    
    var Dashboard = {
        config: {
            autoRefreshInterval: 30000, // 30 Sekunden
            endpoints: {
                liveStats: 'index.php?page=upkeep/dashboard&func=live_stats',
                recentActivities: 'index.php?page=upkeep/dashboard&func=recent_activities'
            }
        },
        
        state: {
            autoRefreshActive: false,
            intervalId: null,
            isInitialized: false
        },
        
        elements: {},
        
        init: function() {
            var self = this;
            
            if (this.state.isInitialized) {
                console.log('Dashboard: Already initialized, skipping...');
                return;
            }
            
            console.log('Dashboard: Starting initialization...');
            
            // Warte kurz, um sicherzustellen dass DOM vollständig ist
            setTimeout(function() {
                self.cacheElements();
                self.bindEvents();
                self.updateLiveTime();
                self.loadRecentActivities();
                self.loadLiveStats();
                self.startLiveTimeUpdate();
                
                // Auto-start refresh wenn gewünscht
                if (localStorage.getItem('upkeep_dashboard_autorefresh') === 'true') {
                    self.startAutoRefresh();
                }
                
                self.state.isInitialized = true;
                console.log('Dashboard: Initialization completed successfully');
            }, 100);
        },
        
        cacheElements: function() {
            console.log('Dashboard: Caching elements...');
            
            this.elements = {
                $liveTime: $('#live-time'),
                $autoRefreshBtn: $('#auto-refresh'),
                $refreshActivitiesBtn: $('#refresh-activities'),
                $recentActivities: $('#recent-activities'),
                $blockedIpsCount: $('#blocked-ips-count'),
                $threatsToday: $('#threats-today-count'),
                $allowedIpsCount: $('#allowed-ips-count'),
                $statusCards: $('.status-card')
            };
            
            // Debug: Zeige gefundene Elemente
            console.log('Dashboard: Found elements:', {
                liveTime: this.elements.$liveTime.length,
                autoRefreshBtn: this.elements.$autoRefreshBtn.length,
                refreshActivitiesBtn: this.elements.$refreshActivitiesBtn.length,
                recentActivities: this.elements.$recentActivities.length,
                blockedIpsCount: this.elements.$blockedIpsCount.length,
                threatsToday: this.elements.$threatsToday.length,
                statusCards: this.elements.$statusCards.length
            });
        },
        
        
        bindEvents: function() {
            var self = this;
            
            // Auto-Refresh Toggle
            if (this.elements.$autoRefreshBtn.length) {
                this.elements.$autoRefreshBtn.on('click', function(e) {
                    e.preventDefault();
                    self.toggleAutoRefresh();
                });
            }
            
            // Manual Activity Refresh
            if (this.elements.$refreshActivitiesBtn.length) {
                this.elements.$refreshActivitiesBtn.on('click', function(e) {
                    e.preventDefault();
                    self.loadRecentActivities();
                });
            }
            
            // Keyboard Shortcuts
            $(document).on('keydown', function(e) {
                if (e.ctrlKey || e.metaKey) {
                    switch(e.which) {
                        case 82: // R
                            e.preventDefault();
                            self.refreshAll();
                            break;
                        case 76: // L
                            e.preventDefault();
                            self.toggleAutoRefresh();
                            break;
                    }
                }
            });
            
            // Visibility API für Pause bei inaktivem Tab
            $(document).on('visibilitychange', function() {
                if (document.hidden && self.state.autoRefreshActive) {
                    self.pauseAutoRefresh();
                } else if (!document.hidden && self.state.autoRefreshActive) {
                    self.resumeAutoRefresh();
                }
            });
        },
        
        updateLiveTime: function() {
            if (!this.elements.$liveTime.length) return;
            
            var now = new Date();
            var timeString = now.toLocaleTimeString('de-DE', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            this.elements.$liveTime.text(timeString);
        },
        
        startLiveTimeUpdate: function() {
            var self = this;
            // Update time every second
            setInterval(function() {
                self.updateLiveTime();
            }, 1000);
        },
        
        loadRecentActivities: function() {
            var self = this;
            
            if (!this.elements.$recentActivities.length) {
                console.warn('Dashboard: #recent-activities element not found');
                return;
            }
            
            console.log('Dashboard: Loading recent activities...');
            this.showLoading(this.elements.$recentActivities);
            
            $.ajax({
                url: this.config.endpoints.recentActivities,
                type: 'GET',
                dataType: 'html',
                timeout: 15000,
                success: function(html) {
                    console.log('Dashboard: Activities loaded successfully');
                    if (html && html.trim() !== '') {
                        self.elements.$recentActivities.html(html);
                        self.animateUpdate(self.elements.$recentActivities);
                    } else {
                        self.elements.$recentActivities.html('<div class="text-center text-muted">Keine Daten verfügbar</div>');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Dashboard: Error loading activities:', {
                        status: status,
                        error: error,
                        responseText: xhr.responseText
                    });
                    self.showError(self.elements.$recentActivities, 'Fehler beim Laden der Aktivitäten: ' + error);
                }
            });
        },
        
        loadLiveStats: function() {
            var self = this;
            
            console.log('Dashboard: Loading live stats...');
            
            $.ajax({
                url: this.config.endpoints.liveStats,
                type: 'GET',
                dataType: 'json',
                timeout: 15000,
                success: function(data) {
                    console.log('Dashboard: Stats loaded successfully', data);
                    if (data && typeof data === 'object') {
                        self.updateStats(data);
                    } else {
                        console.warn('Dashboard: Invalid stats data received', data);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Dashboard: Error loading stats:', {
                        status: status,
                        error: error,
                        responseText: xhr.responseText
                    });
                    self.showNotification('Fehler beim Laden der Statistiken: ' + error, 'error');
                }
            });
        },
        
        updateStats: function(data) {
            var self = this;
            
            console.log('Dashboard: Updating stats with data:', data);
            
            // Update counters with animation - nur wenn Elemente existieren
            if (this.elements.$blockedIpsCount.length && data.blocked_ips !== undefined) {
                console.log('Dashboard: Updating blocked IPs count:', data.blocked_ips);
                this.animateCounter(this.elements.$blockedIpsCount, data.blocked_ips);
            }
            
            if (this.elements.$threatsToday.length && data.threats_today !== undefined) {
                console.log('Dashboard: Updating threats today count:', data.threats_today);
                this.animateCounter(this.elements.$threatsToday, data.threats_today);
            }
            
            if (this.elements.$allowedIpsCount.length && data.allowed_ips !== undefined) {
                console.log('Dashboard: Updating allowed IPs count:', data.allowed_ips);
                this.animateCounter(this.elements.$allowedIpsCount, data.allowed_ips);
            }
            
            // Animate status cards - nur wenn vorhanden
            if (this.elements.$statusCards.length) {
                this.elements.$statusCards.addClass('updated');
                setTimeout(function() {
                    self.elements.$statusCards.removeClass('updated');
                }, 600);
            }
        },
        
        animateCounter: function($element, newValue) {
            if (!$element || !$element.length) {
                console.warn('Dashboard: animateCounter called with invalid element');
                return;
            }
            
            var currentValue = parseInt($element.text()) || 0;
            
            if (currentValue === newValue) return;
            
            var duration = 800;
            var steps = 20;
            var stepValue = (newValue - currentValue) / steps;
            var stepDuration = duration / steps;
            
            var step = 0;
            var timer = setInterval(function() {
                step++;
                var value = Math.round(currentValue + (stepValue * step));
                $element.text(step === steps ? newValue : value);
                
                if (step === steps) {
                    clearInterval(timer);
                }
            }, stepDuration);
        },
        
        toggleAutoRefresh: function() {
            if (this.state.autoRefreshActive) {
                this.stopAutoRefresh();
            } else {
                this.startAutoRefresh();
            }
        },
        
        startAutoRefresh: function() {
            var self = this;
            this.state.autoRefreshActive = true;
            localStorage.setItem('upkeep_dashboard_autorefresh', 'true');
            
            this.state.intervalId = setInterval(function() {
                self.refreshAll();
            }, this.config.autoRefreshInterval);
            
            this.updateAutoRefreshButton();
            this.showNotification('Auto-Refresh aktiviert', 'success');
        },
        
        stopAutoRefresh: function() {
            this.state.autoRefreshActive = false;
            localStorage.setItem('upkeep_dashboard_autorefresh', 'false');
            
            if (this.state.intervalId) {
                clearInterval(this.state.intervalId);
                this.state.intervalId = null;
            }
            
            this.updateAutoRefreshButton();
            this.showNotification('Auto-Refresh deaktiviert', 'info');
        },
        
        pauseAutoRefresh: function() {
            if (this.state.intervalId) {
                clearInterval(this.state.intervalId);
                this.state.intervalId = null;
            }
        },
        
        resumeAutoRefresh: function() {
            var self = this;
            if (this.state.autoRefreshActive && !this.state.intervalId) {
                this.state.intervalId = setInterval(function() {
                    self.refreshAll();
                }, this.config.autoRefreshInterval);
            }
        },
        
        updateAutoRefreshButton: function() {
            if (!this.elements.$autoRefreshBtn.length) return;
            
            var $btn = this.elements.$autoRefreshBtn;
            
            if (this.state.autoRefreshActive) {
                $btn.removeClass('btn-default').addClass('btn-success active');
                $btn.html('<i class="rex-icon fa-pause"></i> Stop');
                $btn.attr('title', 'Auto-Refresh stoppen (Strg+L)');
            } else {
                $btn.removeClass('btn-success active').addClass('btn-default');
                $btn.html('<i class="rex-icon fa-refresh"></i> Live');
                $btn.attr('title', 'Auto-Refresh starten (Strg+L)');
            }
        },
        
        refreshAll: function() {
            this.updateLiveTime();
            this.loadLiveStats();
            this.loadRecentActivities();
        },
        
        showLoading: function($element) {
            $element.html(
                '<div class="text-center" style="padding: 40px;">' +
                    '<div class="spinner"></div>' +
                    '<p style="margin-top: 15px; color: var(--upkeep-text-secondary);">Lädt...</p>' +
                '</div>'
            );
        },
        
        showError: function($element, message) {
            $element.html(
                '<div class="alert alert-warning">' +
                    '<i class="rex-icon fa-exclamation-triangle"></i> ' +
                    message +
                '</div>'
            );
        },
        
        animateUpdate: function($element) {
            $element.css({
                'opacity': '0.7',
                'transform': 'scale(0.98)'
            });
            
            setTimeout(function() {
                $element.css({
                    'opacity': '1',
                    'transform': 'scale(1)',
                    'transition': 'all 0.3s ease'
                });
            }, 100);
            
            setTimeout(function() {
                $element.css('transition', '');
            }, 400);
        },
        
        showNotification: function(message, type) {
            type = type || 'info';
            
            // Verwende REDAXO's Notification System falls verfügbar
            if (typeof rex !== 'undefined' && rex.notification) {
                rex.notification.show(message, type);
                return;
            }
            
            // Fallback: Console Log
            console.log('Dashboard: ' + message);
            
            // Einfache visuelle Feedback
            var $notification = $('<div class="alert alert-' + type + ' dashboard-notification">' +
                '<i class="rex-icon fa-info-circle"></i> ' + message +
            '</div>');
            
            $notification.css({
                'position': 'fixed',
                'top': '20px',
                'right': '20px',
                'z-index': '9999',
                'min-width': '300px',
                'opacity': '0',
                'transform': 'translateX(100%)',
                'transition': 'all 0.3s ease'
            });
            
            $('body').append($notification);
            
            // Animate in
            setTimeout(function() {
                $notification.css({
                    'opacity': '1',
                    'transform': 'translateX(0)'
                });
            }, 100);
            
            // Auto-remove
            setTimeout(function() {
                $notification.css({
                    'opacity': '0',
                    'transform': 'translateX(100%)'
                });
                setTimeout(function() {
                    $notification.remove();
                }, 300);
            }, 3000);
        }
    };
    
    // Initialize Dashboard
    Dashboard.init();
    
    // Global access for debugging
    window.UpkeepDashboard = Dashboard;
    
});
