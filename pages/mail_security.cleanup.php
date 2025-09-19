<?php

$addon = rex_addon::get('upkeep');

// Variablen initialisieren
$error = '';
$success = '';

// Cleanup-Aktionen
if (rex_post('cleanup-action', 'string')) {
    $action = rex_post('cleanup-action', 'string');
    $days = max(1, rex_post('cleanup-days', 'int', 30));
    
    try {
        $sql = rex_sql::factory();
        $cutoffDate = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        $affectedRows = 0;
        
        switch ($action) {
            case 'rate-limit':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_rate_limit') . " WHERE created_at < ?", [$cutoffDate]);
                $affectedRows = $sql->getRows();
                $success = $affectedRows . ' ' . $addon->i18n('upkeep_cleanup_rate_limit_deleted', $days);
                break;
                
            case 'threat-log':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail_%' AND created_at < ?", [$cutoffDate]);
                $affectedRows = $sql->getRows();
                $success = $affectedRows . ' ' . $addon->i18n('upkeep_cleanup_threat_log_deleted', $days);
                break;
                
            case 'detailed-log':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_threat_log') . " WHERE created_at < ?", [$cutoffDate]);
                $affectedRows = $sql->getRows();
                $success = $affectedRows . ' ' . $addon->i18n('upkeep_cleanup_detailed_log_deleted', $days);
                break;
                
            case 'expired-blocklist':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blocklist') . " WHERE expires_at IS NOT NULL AND expires_at < NOW()");
                $affectedRows = $sql->getRows();
                $success = $affectedRows . ' ' . $addon->i18n('upkeep_cleanup_expired_blocklist_deleted');
                break;
                
            case 'all-mail-data':
                // Alle Mail-Security-Daten löschen
                $totalDeleted = 0;
                
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_rate_limit') . " WHERE created_at < ?", [$cutoffDate]);
                $totalDeleted += $sql->getRows();
                
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail_%' AND created_at < ?", [$cutoffDate]);
                $totalDeleted += $sql->getRows();
                
                try {
                    $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_threat_log') . " WHERE created_at < ?", [$cutoffDate]);
                    $totalDeleted += $sql->getRows();
                } catch (Exception $e) {
                    // Tabelle existiert möglicherweise nicht
                }
                
                $success = $totalDeleted . ' ' . $addon->i18n('upkeep_cleanup_all_mail_data_deleted', $days);
                break;
                
            default:
                $error = $addon->i18n('upkeep_cleanup_unknown_action');
        }
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_cleanup_error') . ' ' . $e->getMessage();
    }
}

// Statistiken optimieren
if (rex_post('optimize-action', 'string') === '1') {
    try {
        $sql = rex_sql::factory();
        $tablesOptimized = 0;
        
        $tables = [
            rex::getTable('upkeep_mail_rate_limit'),
            rex::getTable('upkeep_mail_badwords'), 
            rex::getTable('upkeep_mail_blocklist'),
            rex::getTable('upkeep_mail_threat_log'),
            rex::getTable('upkeep_ips_threat_log')
        ];
        
        foreach ($tables as $table) {
            try {
                $sql->setQuery("OPTIMIZE TABLE `{$table}`");
                $tablesOptimized++;
            } catch (Exception $e) {
                // Tabelle existiert möglicherweise nicht
            }
        }
        
        $success = $tablesOptimized . ' ' . $addon->i18n('upkeep_cleanup_tables_optimized');
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_cleanup_optimization_error') . ' ' . $e->getMessage();
    }
}

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
}

// Datenbankstatistiken laden
$stats = [];
try {
    $sql = rex_sql::factory();
    
    // Rate-Limit-Statistiken
    $sql->setQuery("SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM " . rex::getTable('upkeep_mail_rate_limit'));
    if ($sql->getRows() > 0) {
        $stats['rate_limit'] = [
            'count' => (int) $sql->getValue('count'),
            'oldest' => $sql->getValue('oldest'),
            'newest' => $sql->getValue('newest')
        ];
    }
    
    // Mail-Threat-Log-Statistiken
    $sql->setQuery("SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail_%'");
    if ($sql->getRows() > 0) {
        $stats['threat_log'] = [
            'count' => (int) $sql->getValue('count'),
            'oldest' => $sql->getValue('oldest'),
            'newest' => $sql->getValue('newest')
        ];
    }
    
    // Detaillierte Mail-Logs
    try {
        $sql->setQuery("SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM " . rex::getTable('upkeep_mail_threat_log'));
        if ($sql->getRows() > 0) {
            $stats['detailed_log'] = [
                'count' => (int) $sql->getValue('count'),
                'oldest' => $sql->getValue('oldest'),
                'newest' => $sql->getValue('newest')
            ];
        }
    } catch (Exception $e) {
        // Tabelle existiert noch nicht
    }
    
    // Badwords-Statistiken
    $sql->setQuery("SELECT COUNT(*) as total, COUNT(CASE WHEN status = 1 THEN 1 END) as active FROM " . rex::getTable('upkeep_mail_badwords'));
    if ($sql->getRows() > 0) {
        $stats['badwords'] = [
            'total' => (int) $sql->getValue('total'),
            'active' => (int) $sql->getValue('active')
        ];
    }
    
    // Blocklist-Statistiken
    $sql->setQuery("SELECT COUNT(*) as total, COUNT(CASE WHEN status = 1 THEN 1 END) as active, COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN 1 END) as expired FROM " . rex::getTable('upkeep_mail_blocklist'));
    if ($sql->getRows() > 0) {
        $stats['blocklist'] = [
            'total' => (int) $sql->getValue('total'),
            'active' => (int) $sql->getValue('active'),
            'expired' => (int) $sql->getValue('expired')
        ];
    }
    
} catch (Exception $e) {
    // Ignore
}

// Statistiken anzeigen
$content = '<div class="row">';

if (isset($stats['rate_limit'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-info">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">' . $addon->i18n('upkeep_cleanup_rate_limit_data') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['rate_limit']['count']) . '</strong> ' . $addon->i18n('upkeep_entries') . '</p>';
    if ($stats['rate_limit']['oldest']) {
        $content .= '<p><small>' . $addon->i18n('upkeep_oldest') . ' ' . rex_formatter::strftime(strtotime($stats['rate_limit']['oldest']), 'date') . '</small></p>';
        $content .= '<p><small>' . $addon->i18n('upkeep_newest') . ' ' . rex_formatter::strftime(strtotime($stats['rate_limit']['newest']), 'date') . '</small></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['threat_log'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-warning">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">' . $addon->i18n('upkeep_cleanup_threat_logs') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['threat_log']['count']) . '</strong> ' . $addon->i18n('upkeep_cleanup_mail_threats') . '</p>';
    if ($stats['threat_log']['oldest']) {
        $content .= '<p><small>' . $addon->i18n('upkeep_oldest') . ' ' . rex_formatter::strftime(strtotime($stats['threat_log']['oldest']), 'date') . '</small></p>';
        $content .= '<p><small>' . $addon->i18n('upkeep_newest') . ' ' . rex_formatter::strftime(strtotime($stats['threat_log']['newest']), 'date') . '</small></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['badwords'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-success">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">' . $addon->i18n('upkeep_badwords') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['badwords']['total']) . '</strong> ' . $addon->i18n('upkeep_total') . '</p>';
    $content .= '<p><strong>' . number_format($stats['badwords']['active']) . '</strong> ' . $addon->i18n('upkeep_status_active') . '</p>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['blocklist'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-danger">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">' . $addon->i18n('upkeep_cleanup_blocklist') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['blocklist']['total']) . '</strong> ' . $addon->i18n('upkeep_total') . '</p>';
    $content .= '<p><strong>' . number_format($stats['blocklist']['active']) . '</strong> ' . $addon->i18n('upkeep_status_active') . '</p>';
    if ($stats['blocklist']['expired'] > 0) {
        $content .= '<p><span class="text-warning"><strong>' . number_format($stats['blocklist']['expired']) . '</strong> ' . $addon->i18n('upkeep_status_expired') . '</span></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_cleanup_database_statistics'), false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Cleanup-Aktionen
$content = '<div class="row">';

// Rate-Limit-Cleanup
$content .= '<div class="col-md-6">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-clock-o"></i> ' . $addon->i18n('upkeep_cleanup_rate_limit_cleanup') . '</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>' . $addon->i18n('upkeep_cleanup_rate_limit_description') . '</p>';
$content .= '<div class="form-group">';
$content .= '<label>' . $addon->i18n('upkeep_cleanup_data_older_than_days') . '</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="7" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="rate-limit" />';
$content .= '<button type="submit" class="btn btn-info" onclick="return confirm(\'' . $addon->i18n('upkeep_cleanup_confirm_rate_limit') . '\')">' . $addon->i18n('upkeep_cleanup_rate_limit_cleanup') . '</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

// Threat-Log-Cleanup
$content .= '<div class="col-md-6">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-warning">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_cleanup_threat_log_cleanup') . '</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>' . $addon->i18n('upkeep_cleanup_threat_log_description') . '</p>';
$content .= '<div class="form-group">';
$content .= '<label>' . $addon->i18n('upkeep_cleanup_data_older_than_days') . '</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="threat-log" />';
$content .= '<button type="submit" class="btn btn-warning" onclick="return confirm(\'' . $addon->i18n('upkeep_cleanup_confirm_threat_log') . '\')">' . $addon->i18n('upkeep_cleanup_threat_log_cleanup') . '</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row">';

// Abgelaufene Blocklist-Einträge
if (isset($stats['blocklist']) && $stats['blocklist']['expired'] > 0) {
    $content .= '<div class="col-md-6">';
    $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
    $content .= '<div class="panel panel-danger">';
    $content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-ban"></i> ' . $addon->i18n('upkeep_cleanup_expired_blocklist_entries') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p>' . $addon->i18n('upkeep_cleanup_expired_blocklist_description') . '</p>';
    $content .= '<p><strong>' . $stats['blocklist']['expired'] . '</strong> ' . $addon->i18n('upkeep_cleanup_expired_entries_found') . '</p>';
    $content .= '</div>';
    $content .= '<div class="panel-footer">';
    $content .= '<input type="hidden" name="cleanup-action" value="expired-blocklist" />';
    $content .= '<button type="submit" class="btn btn-danger" onclick="return confirm(\'' . $addon->i18n('upkeep_cleanup_confirm_expired_blocklist') . '\')">' . $addon->i18n('upkeep_cleanup_delete_expired_entries') . '</button>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</form>';
    $content .= '</div>';
}

// Detaillierte Logs
if (isset($stats['detailed_log']) && $stats['detailed_log']['count'] > 0) {
    $content .= '<div class="col-md-6">';
    $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-list"></i> ' . $addon->i18n('upkeep_cleanup_detailed_mail_logs') . '</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p>' . $addon->i18n('upkeep_cleanup_detailed_logs_description') . '</p>';
    $content .= '<div class="form-group">';
    $content .= '<label>' . $addon->i18n('upkeep_cleanup_data_older_than_days') . '</label>';
    $content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '<div class="panel-footer">';
    $content .= '<input type="hidden" name="cleanup-action" value="detailed-log" />';
    $content .= '<button type="submit" class="btn btn-default" onclick="return confirm(\'' . $addon->i18n('upkeep_cleanup_confirm_detailed_logs') . '\')">' . $addon->i18n('upkeep_cleanup_detailed_logs_cleanup') . '</button>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</form>';
    $content .= '</div>';
}

$content .= '</div>';

// Vollständige Bereinigung
$content .= '<div class="row">';
$content .= '<div class="col-md-8">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-danger">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-trash"></i> ' . $addon->i18n('upkeep_cleanup_full_cleanup') . '</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>' . $addon->i18n('upkeep_cleanup_full_cleanup_warning') . '</p>';
$content .= '<p>' . $addon->i18n('upkeep_cleanup_full_cleanup_note') . '</p>';
$content .= '<div class="form-group">';
$content .= '<label>' . $addon->i18n('upkeep_cleanup_data_older_than_days') . '</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="all-mail-data" />';
$content .= '<button type="submit" class="btn btn-danger" onclick="return confirm(\'' . $addon->i18n('upkeep_cleanup_confirm_full_cleanup') . '\')">' . $addon->i18n('upkeep_cleanup_full_cleanup') . '</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

// Datenbank-Optimierung
$content .= '<div class="col-md-4">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-success">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-cogs"></i> ' . $addon->i18n('upkeep_cleanup_optimize_database') . '</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>' . $addon->i18n('upkeep_cleanup_optimize_description') . '</p>';
$content .= '<p><small>' . $addon->i18n('upkeep_cleanup_optimize_note') . '</small></p>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="optimize-action" value="1" />';
$content .= '<button type="submit" class="btn btn-success">' . $addon->i18n('upkeep_cleanup_optimize_tables') . '</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_cleanup_options'), false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Empfehlungen
$content = '<div class="alert alert-info">';
$content .= '<h4><i class="fa fa-lightbulb-o"></i> ' . $addon->i18n('upkeep_cleanup_recommendations') . '</h4>';
$content .= '<ul>';
$content .= '<li><strong>' . $addon->i18n('upkeep_cleanup_rate_limit_data') . ':</strong> ' . $addon->i18n('upkeep_cleanup_recommendation_rate_limit') . '</li>';
$content .= '<li><strong>' . $addon->i18n('upkeep_cleanup_threat_logs') . ':</strong> ' . $addon->i18n('upkeep_cleanup_recommendation_threat_logs') . '</li>';
$content .= '<li><strong>' . $addon->i18n('upkeep_cleanup_blocklist') . ':</strong> ' . $addon->i18n('upkeep_cleanup_recommendation_blocklist') . '</li>';
$content .= '<li><strong>' . $addon->i18n('upkeep_cleanup_optimization') . ':</strong> ' . $addon->i18n('upkeep_cleanup_recommendation_optimization') . '</li>';
$content .= '<li><strong>' . $addon->i18n('upkeep_cleanup_automation') . ':</strong> ' . $addon->i18n('upkeep_cleanup_recommendation_automation') . '</li>';
$content .= '</ul>';
$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');