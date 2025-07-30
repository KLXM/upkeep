/**
 * Dashboard JavaScript für das Upkeep AddOn
 * Vereinfachte Version mit Reload-Button
 */

jQuery(document).on('rex:ready', function($) {
    'use strict';
    
    console.log('Dashboard: Initializing simplified version...');
    
    var Dashboard = {
        init: function() {
            this.bindEvents();
            this.updateLiveTime();
            this.startLiveTimeUpdate();
            console.log('Dashboard: Initialization completed');
        },
        
        bindEvents: function() {
            var self = this;
            
            // Reload Button
            $('#dashboard-reload').on('click', function(e) {
                e.preventDefault();
                self.reloadPage();
            });
            
            // Keyboard Shortcuts
            $(document).on('keydown', function(e) {
                if (e.ctrlKey || e.metaKey) {
                    switch(e.which) {
                        case 82: // R
                            e.preventDefault();
                            self.reloadPage();
                            break;
                    }
                }
            });
        },
        
        updateLiveTime: function() {
            var $liveTime = $('#live-time');
            if (!$liveTime.length) return;
            
            var now = new Date();
            var timeString = now.toLocaleTimeString('de-DE', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            $liveTime.text(timeString);
        },
        
        startLiveTimeUpdate: function() {
            var self = this;
            // Update time every second
            setInterval(function() {
                self.updateLiveTime();
            }, 1000);
        },
        
        reloadPage: function() {
            // Zeige Loading-Indikator
            this.showReloadIndicator();
            
            // Reload nach kurzer Verzögerung
            setTimeout(function() {
                window.location.reload();
            }, 300);
        },
        
        showReloadIndicator: function() {
            var $btn = $('#dashboard-reload');
            if ($btn.length) {
                var originalHtml = $btn.html();
                $btn.html('<i class="rex-icon fa-spinner fa-spin"></i> Lädt...');
                $btn.prop('disabled', true);
            }
        }
    };
    
    // Initialize Dashboard
    Dashboard.init();
    
    // Global access for debugging
    window.UpkeepDashboard = Dashboard;
    
});
