<?php

use KLXM\Upkeep\MailSecurityFilter;

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
                $success = "{$affectedRows} Rate-Limit-Einträge älter als {$days} Tage wurden gelöscht.";
                break;
                
            case 'threat-log':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail_%' AND created_at < ?", [$cutoffDate]);
                $affectedRows = $sql->getRows();
                $success = "{$affectedRows} Mail-Threat-Log-Einträge älter als {$days} Tage wurden gelöscht.";
                break;
                
            case 'detailed-log':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_threat_log') . " WHERE created_at < ?", [$cutoffDate]);
                $affectedRows = $sql->getRows();
                $success = "{$affectedRows} detaillierte Mail-Log-Einträge älter als {$days} Tage wurden gelöscht.";
                break;
                
            case 'expired-blacklist':
                $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blacklist') . " WHERE expires_at IS NOT NULL AND expires_at < NOW()");
                $affectedRows = $sql->getRows();
                $success = "{$affectedRows} abgelaufene Blacklist-Einträge wurden gelöscht.";
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
                
                $success = "{$totalDeleted} Mail-Security-Einträge älter als {$days} Tage wurden gelöscht.";
                break;
                
            default:
                $error = 'Unbekannte Cleanup-Aktion.';
        }
        
    } catch (Exception $e) {
        $error = 'Fehler beim Cleanup: ' . $e->getMessage();
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
            rex::getTable('upkeep_mail_blacklist'),
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
        
        $success = "{$tablesOptimized} Tabellen wurden optimiert.";
        
    } catch (Exception $e) {
        $error = 'Fehler bei der Optimierung: ' . $e->getMessage();
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
    
    // Blacklist-Statistiken
    $sql->setQuery("SELECT COUNT(*) as total, COUNT(CASE WHEN status = 1 THEN 1 END) as active, COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN 1 END) as expired FROM " . rex::getTable('upkeep_mail_blacklist'));
    if ($sql->getRows() > 0) {
        $stats['blacklist'] = [
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
    $content .= '<div class="panel-heading"><h4 class="panel-title">Rate-Limit-Daten</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['rate_limit']['count']) . '</strong> Einträge</p>';
    if ($stats['rate_limit']['oldest']) {
        $content .= '<p><small>Ältester: ' . rex_formatter::strftime(strtotime($stats['rate_limit']['oldest']), 'date') . '</small></p>';
        $content .= '<p><small>Neuester: ' . rex_formatter::strftime(strtotime($stats['rate_limit']['newest']), 'date') . '</small></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['threat_log'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-warning">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">Threat-Logs</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['threat_log']['count']) . '</strong> Mail-Threats</p>';
    if ($stats['threat_log']['oldest']) {
        $content .= '<p><small>Ältester: ' . rex_formatter::strftime(strtotime($stats['threat_log']['oldest']), 'date') . '</small></p>';
        $content .= '<p><small>Neuester: ' . rex_formatter::strftime(strtotime($stats['threat_log']['newest']), 'date') . '</small></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['badwords'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-success">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">Badwords</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['badwords']['total']) . '</strong> gesamt</p>';
    $content .= '<p><strong>' . number_format($stats['badwords']['active']) . '</strong> aktiv</p>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

if (isset($stats['blacklist'])) {
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-danger">';
    $content .= '<div class="panel-heading"><h4 class="panel-title">Blacklist</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>' . number_format($stats['blacklist']['total']) . '</strong> gesamt</p>';
    $content .= '<p><strong>' . number_format($stats['blacklist']['active']) . '</strong> aktiv</p>';
    if ($stats['blacklist']['expired'] > 0) {
        $content .= '<p><span class="text-warning"><strong>' . number_format($stats['blacklist']['expired']) . '</strong> abgelaufen</span></p>';
    }
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', 'Datenbank-Statistiken', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Cleanup-Aktionen
$content = '<div class="row">';

// Rate-Limit-Cleanup
$content .= '<div class="col-md-6">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-clock-o"></i> Rate-Limit-Daten bereinigen</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>Entfernt alte Rate-Limit-Einträge zur Optimierung der Datenbank.</p>';
$content .= '<div class="form-group">';
$content .= '<label>Daten älter als (Tage):</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="7" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="rate-limit" />';
$content .= '<button type="submit" class="btn btn-info" onclick="return confirm(\'Rate-Limit-Daten wirklich löschen?\')">Rate-Limit-Daten bereinigen</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

// Threat-Log-Cleanup
$content .= '<div class="col-md-6">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-warning">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-exclamation-triangle"></i> Threat-Logs bereinigen</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>Entfernt alte Mail-Threat-Log-Einträge. <strong>Vorsicht:</strong> Daten gehen verloren!</p>';
$content .= '<div class="form-group">';
$content .= '<label>Daten älter als (Tage):</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="threat-log" />';
$content .= '<button type="submit" class="btn btn-warning" onclick="return confirm(\'Threat-Log-Daten wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden!\')">Threat-Logs bereinigen</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row">';

// Abgelaufene Blacklist-Einträge
if (isset($stats['blacklist']) && $stats['blacklist']['expired'] > 0) {
    $content .= '<div class="col-md-6">';
    $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
    $content .= '<div class="panel panel-danger">';
    $content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-ban"></i> Abgelaufene Blacklist-Einträge</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p>Entfernt automatisch alle abgelaufenen Blacklist-Einträge.</p>';
    $content .= '<p><strong>' . $stats['blacklist']['expired'] . '</strong> abgelaufene Einträge gefunden.</p>';
    $content .= '</div>';
    $content .= '<div class="panel-footer">';
    $content .= '<input type="hidden" name="cleanup-action" value="expired-blacklist" />';
    $content .= '<button type="submit" class="btn btn-danger" onclick="return confirm(\'Abgelaufene Blacklist-Einträge wirklich löschen?\')">Abgelaufene Einträge löschen</button>';
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
    $content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-list"></i> Detaillierte Mail-Logs</h4></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p>Bereinigt detaillierte Mail-Threat-Logs (separate Tabelle).</p>';
    $content .= '<div class="form-group">';
    $content .= '<label>Daten älter als (Tage):</label>';
    $content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '<div class="panel-footer">';
    $content .= '<input type="hidden" name="cleanup-action" value="detailed-log" />';
    $content .= '<button type="submit" class="btn btn-default" onclick="return confirm(\'Detaillierte Log-Daten wirklich löschen?\')">Detaillierte Logs bereinigen</button>';
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
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-trash"></i> Vollständige Mail-Security-Bereinigung</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p><strong>Achtung:</strong> Löscht alle Mail-Security-Daten (Rate-Limits, Threat-Logs, detaillierte Logs) älter als die angegebenen Tage.</p>';
$content .= '<p>Badwords und Blacklist-Einträge bleiben erhalten.</p>';
$content .= '<div class="form-group">';
$content .= '<label>Daten älter als (Tage):</label>';
$content .= '<input type="number" class="form-control" name="cleanup-days" value="30" min="1" max="365" />';
$content .= '</div>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="cleanup-action" value="all-mail-data" />';
$content .= '<button type="submit" class="btn btn-danger" onclick="return confirm(\'ALLE Mail-Security-Daten wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden!\')">Vollständige Bereinigung</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

// Datenbank-Optimierung
$content .= '<div class="col-md-4">';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<div class="panel panel-success">';
$content .= '<div class="panel-heading"><h4 class="panel-title"><i class="fa fa-cogs"></i> Datenbank optimieren</h4></div>';
$content .= '<div class="panel-body">';
$content .= '<p>Optimiert alle Mail-Security-Tabellen für bessere Performance.</p>';
$content .= '<p><small>Kann bei großen Datenmengen einige Zeit dauern.</small></p>';
$content .= '</div>';
$content .= '<div class="panel-footer">';
$content .= '<input type="hidden" name="optimize-action" value="1" />';
$content .= '<button type="submit" class="btn btn-success">Tabellen optimieren</button>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';
$content .= '</div>';

$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', 'Cleanup-Optionen', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Empfehlungen
$content = '<div class="alert alert-info">';
$content .= '<h4><i class="fa fa-lightbulb-o"></i> Empfehlungen</h4>';
$content .= '<ul>';
$content .= '<li><strong>Rate-Limit-Daten:</strong> Können täglich bereinigt werden (7 Tage aufbewahren)</li>';
$content .= '<li><strong>Threat-Logs:</strong> Sollten für Sicherheitsanalysen mindestens 30-90 Tage aufbewahrt werden</li>';
$content .= '<li><strong>Blacklist-Einträge:</strong> Abgelaufene Einträge können sicher gelöscht werden</li>';
$content .= '<li><strong>Optimierung:</strong> Sollte regelmäßig (wöchentlich) durchgeführt werden</li>';
$content .= '<li><strong>Automatisierung:</strong> Richten Sie Cronjobs für regelmäßige Bereinigung ein</li>';
$content .= '</ul>';
$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');