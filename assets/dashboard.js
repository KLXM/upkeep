/**
 * Dashboard JavaScript für das Upkeep AddOn
 * Vereinfachte Version ohne Live-Time
 */

jQuery(document).on('rex:ready', function($) {
    'use strict';
    
    console.log('Dashboard: Initializing...');
    
    var Dashboard = {
        init: function() {
            this.bindEvents();
            console.log('Dashboard: Initialization completed');
        },
        
        bindEvents: function() {
            var self = this;
            
            // Reload Button
            $('#dashboard-reload').on('click', function(e) {
                e.preventDefault();
                self.reloadPage();
            });
            
            // Status Card Links - Accessibility Enhancement
            $('.status-card-link').on('keydown', function(e) {
                if (e.which === 13 || e.which === 32) { // Enter or Space
                    e.preventDefault();
                    window.location.href = $(this).attr('href');
                }
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
        
        reloadPage: function() {
            console.log('Dashboard: Reloading page...');
            
            // Visuelles Feedback
            var $button = $('#dashboard-reload');
            var originalText = $button.html();
            
            $button.prop('disabled', true)
                   .html('<i class="rex-icon fa-spinner fa-spin"></i> Aktualisiere...');
            
            // Page reload
            setTimeout(function() {
                window.location.reload();
            }, 500);
        }
    };
    
    // Initialize Dashboard
    Dashboard.init();
    
    // Global Dashboard object for external access
    window.UpkeepDashboard = Dashboard;
});
    
    // Global access for debugging
    window.UpkeepDashboard = Dashboard;
    
});
