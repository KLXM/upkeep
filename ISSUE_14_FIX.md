# Fix für SQL-Fehler "Unknown column 'expires_at'" (Issue #14)

## Problem
Nach dem Update auf Version 1.4.0 erscheint folgender Fehler:

```
Error | IPS: Error checking Positivliste: Error while executing statement "SELECT ip_address, ip_range, expires_at FROM rex_upkeep_ips_positivlisteWHERE status = 1 AND (expires_at IS NULL OR expires_at > NOW())" using params []! SQLSTATE[42S22]: Column not found: 1054 Unknown column 'expires_at' in 'SELECT'
```

## Ursache
Bei bestehenden Installationen wurde die neue Tabelle `upkeep_ips_positivliste` nicht korrekt erstellt, da das Update-Script unvollständig war.

## Lösung

### Schritt 1: AddOn neu installieren (empfohlen)
1. Gehe zu **System > AddOns**
2. Beim Upkeep AddOn auf **Neu installieren** klicken
3. Das AddOn wird die fehlenden Tabellen automatisch erstellen

### Schritt 2: Manuelle Datenbank-Reparatur (falls nötig)
Falls Schritt 1 nicht funktioniert, führe diese SQL-Befehle in der Datenbank aus:

```sql
-- Positivliste-Tabelle erstellen
CREATE TABLE IF NOT EXISTS `rex_upkeep_ips_positivliste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `ip_range` varchar(50) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `category` enum('admin','cdn','monitoring','api','trusted','captcha_verified_temp') NOT NULL DEFAULT 'trusted',
  `expires_at` datetime DEFAULT NULL,
  `status` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip_lookup` (`ip_address`, `status`),
  KEY `range_lookup` (`ip_range`, `status`),
  KEY `expires_lookup` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Admin-IP automatisch hinzufügen (IP-Adresse anpassen!)
INSERT IGNORE INTO `rex_upkeep_ips_positivliste` 
  (`ip_address`, `description`, `category`, `status`, `created_at`, `updated_at`) 
VALUES 
  ('DEINE_IP_HIER', 'Admin-IP bei Reparatur hinzugefügt', 'admin', 1, NOW(), NOW());
```

### Schritt 3: Verifizierung
1. Gehe zu **Upkeep > IPS > Positivliste**
2. Prüfe, ob die Seite ohne Fehler lädt
3. Deine Admin-IP sollte automatisch in der Liste stehen

## Technische Details
- **Problem:** Fehlende `expires_at` Spalte in `upkeep_ips_positivliste` Tabelle
- **Fix:** Vollständiges Update-Script mit allen IPS-Tabellen
- **Version:** Behoben in v1.4.0+

## Vorbeugung
Künftige Updates werden durch das verbesserte Update-Script automatisch alle benötigten Tabellen-Änderungen durchführen.
