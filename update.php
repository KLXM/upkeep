<?php

// Update-Script für Upkeep AddOn v1.4.0+
// Bindet install.php ein für einheitliche Wartung der Tabellen und Konfiguration

// Installation ausführen (enthält alle Tabellen und Standardkonfiguration)
require_once __DIR__ . '/install.php';

// v2.2.2: Mail Security Patterns verfeinern - zu breite Patterns ersetzen
try {
    $sql = rex_sql::factory();
    
    // Alte zu breite Meta-Tag Pattern durch spezifischere ersetzen
    $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_mail_default_patterns') . ' 
                   WHERE pattern LIKE "%<meta[^>]*>%i" AND pattern NOT LIKE "%http-equiv%"');
    
    if ($sql->getRows() > 0) {
        $id = $sql->getValue('id');
        $updateSql = rex_sql::factory();
        $updateSql->setTable(rex::getTable('upkeep_mail_default_patterns'));
        $updateSql->setWhere(['id' => $id]);
        $updateSql->setValue('pattern', '/<meta[^>]*http-equiv\s*=\s*["\']?(refresh|set-cookie|content-security-policy)["\']?[^>]*>/i');
        $updateSql->setValue('description', 'Meta HTTP-Equiv Injection');
        $updateSql->setValue('updated_at', date('Y-m-d H:i:s'));
        $updateSql->update();
        
        rex_logger::factory()->log('info', 'Mail Security: Meta-Tag Pattern verfeinert (nur gefährliche http-equiv)');
    }
    
    // Alte zu breite Link-Tag Pattern durch spezifischere ersetzen
    $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_mail_default_patterns') . ' 
                   WHERE pattern LIKE "%<link[^>]*>%i" AND pattern NOT LIKE "%rel%"');
    
    if ($sql->getRows() > 0) {
        $id = $sql->getValue('id');
        $updateSql = rex_sql::factory();
        $updateSql->setTable(rex::getTable('upkeep_mail_default_patterns'));
        $updateSql->setWhere(['id' => $id]);
        $updateSql->setValue('pattern', '/<link[^>]*rel\s*=\s*["\']?(import|preload|prefetch)["\']?[^>]*>/i');
        $updateSql->setValue('description', 'Link Import Injection');
        $updateSql->setValue('updated_at', date('Y-m-d H:i:s'));
        $updateSql->update();
        
        rex_logger::factory()->log('info', 'Mail Security: Link-Tag Pattern verfeinert (nur import/preload/prefetch)');
    }
    
    // Alte zu breite Form-Tag Pattern durch spezifischere ersetzen
    $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_mail_default_patterns') . ' 
                   WHERE pattern LIKE "%<form[^>]*>%i" AND pattern NOT LIKE "%action%"');
    
    if ($sql->getRows() > 0) {
        $id = $sql->getValue('id');
        $updateSql = rex_sql::factory();
        $updateSql->setTable(rex::getTable('upkeep_mail_default_patterns'));
        $updateSql->setWhere(['id' => $id]);
        $updateSql->setValue('pattern', '/<form[^>]*action\s*=\s*["\']?https?:\/\/[^"\'>\s]+["\']?[^>]*>/i');
        $updateSql->setValue('description', 'External Form Action Injection');
        $updateSql->setValue('updated_at', date('Y-m-d H:i:s'));
        $updateSql->update();
        
        rex_logger::factory()->log('info', 'Mail Security: Form-Tag Pattern verfeinert (nur externe Actions)');
    }
    
    // Alte zu breite Data-URI Pattern durch spezifischere ersetzen
    $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_mail_default_patterns') . ' 
                   WHERE pattern LIKE "%data:%[^,]*,%i" AND pattern NOT LIKE "%text/%"');
    
    if ($sql->getRows() > 0) {
        $id = $sql->getValue('id');
        $updateSql = rex_sql::factory();
        $updateSql->setTable(rex::getTable('upkeep_mail_default_patterns'));
        $updateSql->setWhere(['id' => $id]);
        $updateSql->setValue('pattern', '/data:\s*text\/(html|javascript)/i');
        $updateSql->setValue('description', 'Data URI HTML/JS Injection');
        $updateSql->setValue('updated_at', date('Y-m-d H:i:s'));
        $updateSql->update();
        
        rex_logger::factory()->log('info', 'Mail Security: Data-URI Pattern verfeinert (nur HTML/JS)');
    }
    
} catch (Exception $e) {
    rex_logger::factory()->log('error', 'Mail Security Pattern Update Error: ' . $e->getMessage());
}

// Korrektur für Badwords mit ungültigen Severity-Werten
try {
    $sql = rex_sql::factory();
    // Prüfen ob es ungültige Einträge gibt
    $sql->setQuery('SELECT COUNT(*) as count FROM ' . rex::getTable('upkeep_mail_badwords') . ' 
                   WHERE category = "german_spam" AND (severity IS NULL OR severity NOT IN ("low", "medium", "high", "critical"))');
    
    $count = (int) $sql->getValue('count');
    if ($count > 0) {
        // Ungültige Einträge korrigieren
        $sql->setQuery('UPDATE ' . rex::getTable('upkeep_mail_badwords') . ' 
                       SET severity = "medium", updated_at = NOW() 
                       WHERE category = "german_spam" AND (severity IS NULL OR severity NOT IN ("low", "medium", "high", "critical"))');
        
        // Log-Eintrag erstellen
        rex_logger::factory()->log('info', 'Mail Security: ' . $count . ' Badwords mit ungültigen Severity-Werten korrigiert');
    }
} catch (Exception $e) {
    // Fehler beim Aktualisieren loggen
    rex_logger::factory()->log('error', 'Mail Security Badwords Update Error: ' . $e->getMessage());
}
