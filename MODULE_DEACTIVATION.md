# Modul-Deaktivierung - Implementierung

## Übersicht

Das Upkeep AddOn wurde um eine Modulkonfiguration erweitert, die es ermöglicht, einzelne Module zu deaktivieren und deren Navigation sowie Dashboard-Kacheln auszublenden.

## Implementierte Änderungen

### 1. Admin-Einstellungsseite erweitert (`pages/admin_settings.php`)
- Neuer Bereich "Modul-Konfiguration" hinzugefügt
- Checkboxen für Security Advisor, Mail Security und Reporting
- Statusanzeige für deaktivierte Module

### 2. Hauptklasse erweitert (`lib/Upkeep.php`)
- Neue Methode `configureModulePages()` hinzugefügt
- Dynamisches Ausblenden von Seiten basierend auf Konfiguration

### 3. Boot-Datei angepasst (`boot.php`)
- Aufruf der `configureModulePages()` Methode in den Backend-Initialisierungen

### 4. Package-Konfiguration erweitert (`package.yml`)
- Neue Standard-Konfigurationswerte für Module hinzugefügt:
  - `security_advisor_enabled: true`
  - `mail_security_enabled: true` 
  - `reporting_enabled: true`

### 5. Dashboard angepasst (`pages/dashboard.php`)
- Modulstatus beim Laden prüfen
- Security-Sektion nur anzeigen wenn entsprechende Module aktiv
- Mail-Statistiken nur bei aktiviertem Mail Security Modul
- Bedingte Anzeige von Dashboard-Kacheln

### 6. Sprachdateien erweitert
- Deutsche (`lang/de_de.lang`) und englische (`lang/en_gb.lang`) Übersetzungen
- Neue Schlüssel für Modulkonfiguration und Statusmeldungen

## Funktionalität

### Aktivierung/Deaktivierung von Modulen
Administratoren können in den Admin-Einstellungen folgende Module aktivieren/deaktivieren:

1. **Security Advisor**
   - Sicherheitsanalyse und -empfehlungen
   - Dashboard-Kacheln für Sicherheitsstatus

2. **Mail Security** 
   - E-Mail-Schutz vor Spam und Bedrohungen
   - Mail-bezogene Dashboard-Statistiken

3. **Reporting**
   - System-Health-Monitoring
   - E-Mail-Berichte (noch nicht vollständig implementiert)

4. **IPS (Intrusion Prevention System)**
   - Schutz vor Angriffen und verdächtigen Zugriffen
   - Bedrohungsstatistiken und blockierte IPs

### Auswirkungen der Deaktivierung
- **Navigation**: Entsprechende Menüeinträge werden aus der Backend-Navigation entfernt
- **Dashboard**: Zugehörige Dashboard-Kacheln werden ausgeblendet
- **Funktionalität**: Die Hintergrund-Funktionalität bleibt aktiv (z.B. Mail-Filterung)

### Technische Umsetzung
Basierend auf dem REDAXO-Pattern wie im Forcal AddOn:
```php
$page = $this->getProperty('page');
if (isset($page['subpages']['module_name']) && !$moduleEnabled) {
    unset($page['subpages']['module_name']);
}
$this->setProperty('page', $page);
```

## Verwendung

1. Als Administrator zu **Upkeep > Admin-Einstellungen** navigieren
2. Im Bereich "Modul-Konfiguration" gewünschte Module aktivieren/deaktivieren
3. Einstellungen speichern
4. Dashboard und Navigation werden automatisch angepasst

## Konfigurationswerte

Die Modulstatus werden in der AddOn-Konfiguration gespeichert:
- `security_advisor_enabled` (boolean)
- `mail_security_enabled` (boolean) 
- `reporting_enabled` (boolean)
- `ips_enabled` (boolean)

## Testdatei

Eine temporäre Testdatei (`test_module_config.php`) wurde erstellt, um die Funktionalität zu überprüfen. Diese kann nach erfolgreichem Test gelöscht werden.

## Hinweise

- Die Deaktivierung beeinflusst nur die Benutzeroberfläche
- Sicherheitsfunktionen wie Mail-Filterung bleiben im Hintergrund aktiv
- Admin-Berechtigungen werden weiterhin respektiert
- Die Implementierung ist rückwärtskompatibel (Standard: alle Module aktiviert)