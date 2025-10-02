<?php

// Update-Script für Upkeep AddOn v1.4.0+
// Bindet install.php ein für einheitliche Wartung der Tabellen und Konfiguration

// Installation ausführen (enthält alle Tabellen und Standardkonfiguration)
require_once __DIR__ . '/install.php';

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
