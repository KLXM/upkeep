<?php

use KLXM\Upkeep\MailSecurityFilter;

$error = '';
$success = '';
$addon = rex_addon::get('upkeep');

// Konfiguration speichern
if (rex_post('form-submit', 'string') === '1') {
    try {
        // Mail Security Einstellungen
        $addon->setConfig('mail_security_active', (bool) rex_post('mail_security_active', 'int', 0));
        $addon->setConfig('mail_rate_limiting_enabled', (bool) rex_post('mail_rate_limiting_enabled', 'int', 0));
        $addon->setConfig('mail_security_debug', (bool) rex_post('mail_security_debug', 'int', 0));
        $addon->setConfig('mail_security_detailed_logging', (bool) rex_post('mail_security_detailed_logging', 'int', 0));
        
        // Rate-Limiting Konfiguration
        $addon->setConfig('mail_rate_limit_per_minute', max(1, (int) rex_post('rate_limit_per_minute', 'int', 10)));
        $addon->setConfig('mail_rate_limit_per_hour', max(1, (int) rex_post('rate_limit_per_hour', 'int', 50)));
        $addon->setConfig('mail_rate_limit_per_day', max(1, (int) rex_post('rate_limit_per_day', 'int', 200)));
        
        // Erlaubte Sender-Domains
        $allowedDomains = rex_post('allowed_sender_domains', 'string', '');
        $addon->setConfig('mail_allowed_sender_domains', $allowedDomains);
        
        $success = 'Konfiguration erfolgreich gespeichert.';
        
    } catch (Exception $e) {
        $error = 'Fehler beim Speichern: ' . rex_escape($e->getMessage());
    }
}

// Badword hinzufügen
if (rex_post('add-badword', 'string') === '1') {
    $pattern = trim(rex_post('badword_pattern', 'string', ''));
    $severity = rex_post('badword_severity', 'string', 'medium');
    $category = rex_post('badword_category', 'string', 'general');
    $isRegex = (bool) rex_post('badword_is_regex', 'int', 0);
    $description = trim(rex_post('badword_description', 'string', ''));
    
    if (!empty($pattern)) {
        try {
            if (MailSecurityFilter::addBadword($pattern, $severity, $category, $isRegex, $description)) {
                $success = 'Badword erfolgreich hinzugefügt.';
            } else {
                $error = 'Fehler beim Hinzufügen des Badwords. Prüfen Sie das System-Log für Details.';
            }
        } catch (Exception $e) {
            $error = 'Exception beim Hinzufügen des Badwords: ' . rex_escape($e->getMessage());
        }
    } else {
        $error = 'Pattern darf nicht leer sein.';
    }
}

// Badword entfernen
if (rex_post('remove-badword', 'int') > 0) {
    $badwordId = rex_post('remove-badword', 'int');
    if (MailSecurityFilter::removeBadword($badwordId)) {
        $success = 'Badword erfolgreich entfernt.';
    } else {
        $error = 'Fehler beim Entfernen des Badwords.';
    }
}

// E-Mail zur Blacklist hinzufügen
if (rex_post('add-blacklist', 'string') === '1') {
    $email = trim(rex_post('blacklist_email', 'string', ''));
    $domain = trim(rex_post('blacklist_domain', 'string', ''));
    $type = rex_post('blacklist_type', 'string', 'email');
    $severity = rex_post('blacklist_severity', 'string', 'medium');
    $reason = trim(rex_post('blacklist_reason', 'string', ''));
    
    if (!empty($email) || !empty($domain)) {
        if (MailSecurityFilter::addEmailBlacklist($email, $domain, $reason, $severity, $type)) {
            $success = 'Eintrag erfolgreich zur Blacklist hinzugefügt.';
        } else {
            $error = 'Fehler beim Hinzufügen zur Blacklist.';
        }
    } else {
        $error = 'E-Mail-Adresse oder Domain muss angegeben werden.';
    }
}

// Aktuelle Konfiguration laden
$config = [
    'mail_security_active' => $addon->getConfig('mail_security_active', false),
    'mail_rate_limiting_enabled' => $addon->getConfig('mail_rate_limiting_enabled', false),
    'mail_security_debug' => $addon->getConfig('mail_security_debug', false),
    'mail_security_detailed_logging' => $addon->getConfig('mail_security_detailed_logging', false),
    'mail_rate_limit_per_minute' => $addon->getConfig('mail_rate_limit_per_minute', 10),
    'mail_rate_limit_per_hour' => $addon->getConfig('mail_rate_limit_per_hour', 50),
    'mail_rate_limit_per_day' => $addon->getConfig('mail_rate_limit_per_day', 200),
    'mail_allowed_sender_domains' => $addon->getConfig('mail_allowed_sender_domains', ''),
];

// Mail Security Statistiken laden
$stats = MailSecurityFilter::getMailSecurityStats();

echo rex_view::title('Mail Security');

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
}

// Statistiken-Panel
if (!empty($stats)) {
    $content = '<div class="row">';
    
    // Allgemeine Stats
    $content .= '<div class="col-sm-6">';
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h3 class="panel-title">Status (letzte 24h)</h3></div>';
    $content .= '<div class="panel-body">';
    $content .= '<p><strong>Mail Security:</strong> ' . ($stats['active'] ? '<span class="text-success">Aktiv</span>' : '<span class="text-danger">Inaktiv</span>') . '</p>';
    $content .= '<p><strong>Rate Limiting:</strong> ' . ($stats['rate_limiting_enabled'] ? '<span class="text-success">Aktiv</span>' : '<span class="text-danger">Inaktiv</span>') . '</p>';
    if (isset($stats['rate_limiting'])) {
        $content .= '<p><strong>E-Mails versendet:</strong> ' . (int) $stats['rate_limiting']['total_mails'] . '</p>';
        $content .= '<p><strong>Eindeutige IPs:</strong> ' . (int) $stats['rate_limiting']['unique_ips'] . '</p>';
    }
    $content .= '</div></div></div>';
    
    // Bedrohungen
    $content .= '<div class="col-sm-6">';
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h3 class="panel-title">Erkannte Bedrohungen (24h)</h3></div>';
    $content .= '<div class="panel-body">';
    if (!empty($stats['threats_24h'])) {
        foreach ($stats['threats_24h'] as $threat) {
            $severityClass = match($threat['severity']) {
                'critical' => 'text-danger',
                'high' => 'text-warning', 
                'medium' => 'text-info',
                default => 'text-muted'
            };
            $content .= '<p><strong>' . rex_escape($threat['type']) . ':</strong> ';
            $content .= '<span class="' . $severityClass . '">' . $threat['count'] . '</span></p>';
        }
    } else {
        $content .= '<p class="text-muted">Keine Bedrohungen erkannt</p>';
    }
    $content .= '</div></div></div>';
    
    $content .= '</div>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('title', 'Statistiken', false);
    $fragment->setVar('body', $content, false);
    echo $fragment->parse('core/page/section.php');
}

// Konfiguration-Panel
$content = '';
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="form-submit" value="1" />';

// Mail Security Grundeinstellungen
$formElements = [];

$n = [];
$n['label'] = '<label for="mail-security-active">Mail Security aktivieren</label>';
$n['field'] = '<input type="checkbox" id="mail-security-active" name="mail_security_active" value="1"' . ($config['mail_security_active'] ? ' checked="checked"' : '') . ' />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-rate-limiting">Rate Limiting aktivieren</label>';
$n['field'] = '<input type="checkbox" id="mail-rate-limiting" name="mail_rate_limiting_enabled" value="1"' . ($config['mail_rate_limiting_enabled'] ? ' checked="checked"' : '') . ' />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-debug">Debug-Logging aktivieren</label>';
$n['field'] = '<input type="checkbox" id="mail-debug" name="mail_security_debug" value="1"' . ($config['mail_security_debug'] ? ' checked="checked"' : '') . ' />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-detailed-logging">Detailliertes Logging aktivieren</label>';
$n['field'] = '<input type="checkbox" id="mail-detailed-logging" name="mail_security_detailed_logging" value="1"' . ($config['mail_security_detailed_logging'] ? ' checked="checked"' : '') . ' />';
$formElements[] = $n;

// Rate-Limiting Konfiguration
$n = [];
$n['label'] = '<label for="rate-limit-minute">E-Mails pro Minute</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-minute" name="rate_limit_per_minute" value="' . (int) $config['mail_rate_limit_per_minute'] . '" min="1" max="100" />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="rate-limit-hour">E-Mails pro Stunde</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-hour" name="rate_limit_per_hour" value="' . (int) $config['mail_rate_limit_per_hour'] . '" min="1" max="1000" />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="rate-limit-day">E-Mails pro Tag</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-day" name="rate_limit_per_day" value="' . (int) $config['mail_rate_limit_per_day'] . '" min="1" max="10000" />';
$formElements[] = $n;

// Erlaubte Sender-Domains
$n = [];
$n['label'] = '<label for="allowed-domains">Erlaubte Sender-Domains<br><small class="text-muted">Eine Domain pro Zeile. Leer = alle Domains erlaubt</small></label>';
$n['field'] = '<textarea class="form-control" id="allowed-domains" name="allowed_sender_domains" rows="5" placeholder="example.com&#10;mycompany.de">' . rex_escape($config['mail_allowed_sender_domains']) . '</textarea>';
$formElements[] = $n;

// Save Button
$formElements[] = [
    'field' => '<button class="btn btn-primary" type="submit">Konfiguration speichern</button>',
    'label' => ''
];

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', 'Konfiguration', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Badwords-Management Panel
$content = '';

// Badword hinzufügen
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title">Badword hinzufügen</h3></div>';
$content .= '<div class="panel-body">';
$content .= '<input type="hidden" name="add-badword" value="1" />';

$content .= '<div class="row">';
$content .= '<div class="col-sm-4">';
$content .= '<input type="text" class="form-control" name="badword_pattern" placeholder="Pattern (z.B. viagra)" required />';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<select class="form-control" name="badword_severity">';
$content .= '<option value="low">Niedrig</option>';
$content .= '<option value="medium" selected>Mittel</option>';
$content .= '<option value="high">Hoch</option>';
$content .= '<option value="critical">Kritisch</option>';
$content .= '</select>';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<select class="form-control" name="badword_category">';
$content .= '<option value="general">Allgemein</option>';
$content .= '<option value="profanity">Profanity</option>';
$content .= '<option value="pharmaceutical">Pharma</option>';
$content .= '<option value="financial_fraud">Finanzbetrug</option>';
$content .= '<option value="security">Sicherheit</option>';
$content .= '</select>';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<label><input type="checkbox" name="badword_is_regex" value="1" /> RegEx</label>';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<button type="submit" class="btn btn-success">Hinzufügen</button>';
$content .= '</div>';
$content .= '</div>';

$content .= '<div class="row" style="margin-top: 10px;">';
$content .= '<div class="col-sm-12">';
$content .= '<input type="text" class="form-control" name="badword_description" placeholder="Beschreibung (optional)" />';
$content .= '</div>';
$content .= '</div>';

$content .= '</div>';
$content .= '</form>';

// Aktuelle Badwords anzeigen
$badwords = MailSecurityFilter::getBadwords();
if (!empty($badwords)) {
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h3 class="panel-title">Aktuelle Badwords (' . count($badwords) . ')</h3></div>';
    $content .= '<div class="panel-body">';
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th>Pattern</th>';
    $content .= '<th>Kategorie</th>';
    $content .= '<th>Schweregrad</th>';
    $content .= '<th>Typ</th>';
    $content .= '<th>Beschreibung</th>';
    $content .= '<th>Aktionen</th>';
    $content .= '</tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach ($badwords as $badword) {
        $severityClass = match($badword['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $content .= '<tr>';
        $content .= '<td><code>' . rex_escape($badword['pattern']) . '</code></td>';
        $content .= '<td>' . rex_escape($badword['category']) . '</td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($badword['severity']) . '</span></td>';
        $content .= '<td>' . ($badword['is_regex'] ? '<span class="label label-primary">RegEx</span>' : '<span class="label label-default">Text</span>') . '</td>';
        $content .= '<td>' . rex_escape($badword['description'] ?? '') . '</td>';
        $content .= '<td>';
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="remove-badword" value="' . $badword['id'] . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm(\'Badword wirklich löschen?\')">Löschen</button>';
        $content .= '</form>';
        $content .= '</td>';
        $content .= '</tr>';
    }
    
    $content .= '</tbody>';
    $content .= '</table>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', 'Badword-Management', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// E-Mail Blacklist Panel
$content = '';

// Blacklist-Eintrag hinzufügen  
$content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title">E-Mail/Domain zur Blacklist hinzufügen</h3></div>';
$content .= '<div class="panel-body">';
$content .= '<input type="hidden" name="add-blacklist" value="1" />';

$content .= '<div class="row">';
$content .= '<div class="col-sm-3">';
$content .= '<input type="email" class="form-control" name="blacklist_email" placeholder="E-Mail-Adresse" />';
$content .= '</div>';
$content .= '<div class="col-sm-3">';
$content .= '<input type="text" class="form-control" name="blacklist_domain" placeholder="Domain (z.B. spam.com)" />';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<select class="form-control" name="blacklist_type">';
$content .= '<option value="email">E-Mail</option>';
$content .= '<option value="domain">Domain</option>';
$content .= '<option value="pattern">Pattern</option>';
$content .= '</select>';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<select class="form-control" name="blacklist_severity">';
$content .= '<option value="low">Niedrig</option>';
$content .= '<option value="medium" selected>Mittel</option>';
$content .= '<option value="high">Hoch</option>';
$content .= '<option value="critical">Kritisch</option>';
$content .= '</select>';
$content .= '</div>';
$content .= '<div class="col-sm-2">';
$content .= '<button type="submit" class="btn btn-success">Hinzufügen</button>';
$content .= '</div>';
$content .= '</div>';

$content .= '<div class="row" style="margin-top: 10px;">';
$content .= '<div class="col-sm-12">';
$content .= '<input type="text" class="form-control" name="blacklist_reason" placeholder="Grund für Blacklisting (optional)" />';
$content .= '</div>';
$content .= '</div>';

$content .= '</div>';
$content .= '</form>';

// Aktuelle Blacklist anzeigen
try {
    $sql = rex_sql::factory();
    $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_mail_blacklist') . " WHERE status = 1 ORDER BY created_at DESC LIMIT 50");
    
    if ($sql->getRows() > 0) {
        $content .= '<div class="panel panel-default">';
        $content .= '<div class="panel-heading"><h3 class="panel-title">Aktuelle Blacklist (letzte 50 Einträge)</h3></div>';
        $content .= '<div class="panel-body">';
        $content .= '<div class="table-responsive">';
        $content .= '<table class="table table-striped table-hover">';
        $content .= '<thead>';
        $content .= '<tr>';
        $content .= '<th>E-Mail/Domain</th>';
        $content .= '<th>Typ</th>';
        $content .= '<th>Schweregrad</th>';
        $content .= '<th>Grund</th>';
        $content .= '<th>Erstellt</th>';
        $content .= '</tr>';
        $content .= '</thead>';
        $content .= '<tbody>';
        
        while ($sql->hasNext()) {
            $severityClass = match($sql->getValue('severity')) {
                'critical' => 'danger',
                'high' => 'warning',
                'medium' => 'info',
                default => 'default'
            };
            
            $identifier = $sql->getValue('email_address') ?: $sql->getValue('domain') ?: $sql->getValue('pattern');
            
            $content .= '<tr>';
            $content .= '<td><code>' . rex_escape($identifier) . '</code></td>';
            $content .= '<td><span class="label label-default">' . rex_escape($sql->getValue('blacklist_type')) . '</span></td>';
            $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($sql->getValue('severity')) . '</span></td>';
            $content .= '<td>' . rex_escape($sql->getValue('reason') ?? '') . '</td>';
            $content .= '<td>' . rex_formatter::strftime(strtotime($sql->getValue('created_at')), 'date') . '</td>';
            $content .= '</tr>';
            
            $sql->next();
        }
        
        $content .= '</tbody>';
        $content .= '</table>';
        $content .= '</div>';
        $content .= '</div>';
        $content .= '</div>';
    }
} catch (Exception $e) {
    // Blacklist-Tabelle noch nicht verfügbar
}

$fragment = new rex_fragment();
$fragment->setVar('title', 'E-Mail Blacklist', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');