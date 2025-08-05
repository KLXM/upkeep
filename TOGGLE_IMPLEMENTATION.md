# Upkeep AddOn - Domain-Mapping Berechtigungen & Toggle Buttons

## Implementierte Features

### 1. Domain-Mapping eigene Berechtigung

- **Neue Berechtigung**: `upkeep[domain_mapping]`
- **Getrennt von**: `upkeep[domains]` (Domain-Verwaltung)
- **Zugriff**: Separate Kontrolle über Domain-Redirects

#### Konfiguration in package.yml:
```yaml
permissions:
    upkeep[]: 'translate:upkeep[]'
    upkeep[frontend]: 'translate:upkeep[frontend]'
    upkeep[domains]: 'translate:upkeep[domains]'
    upkeep[domain_mapping]: 'translate:upkeep[domain_mapping]'  # NEU
    upkeep[security]: 'translate:upkeep[security]'
```

#### Navigation:
```yaml
domain_mapping:
    title: 'translate:upkeep_domain_mapping_title'
    icon: rex-icon fa fa-share
    perm: upkeep[domain_mapping]  # Geändert von upkeep[domains]
```

### 2. Toggle Buttons für das Dashboard

Wie in GitHub Issue #26 gewünscht - schnelle Toggle-Switches für:
- Frontend Wartungsmodus
- Backend Wartungsmodus  
- Domain-Redirects

#### Features:
- **AJAX-basiert**: Kein Page-Reload erforderlich
- **Berechtigungsprüfung**: Nur verfügbare Toggles werden angezeigt
- **Visuelles Feedback**: Loading-States und Benachrichtigungen
- **Responsive Design**: Funktioniert auf allen Bildschirmgrößen
- **Accessibility**: Keyboard-Navigation unterstützt

#### Berechtigungen für Toggle Buttons:
- **Frontend Toggle**: `upkeep[frontend]` oder Admin
- **Backend Toggle**: Nur Administratoren
- **Domain-Mapping Toggle**: `upkeep[domain_mapping]` oder Admin

## Technische Implementierung

### API-Klasse
- **Datei**: `lib/api_toggle.php`
- **Klasse**: `rex_api_upkeep_toggle`
- **Endpoint**: `rex-api-call=upkeep_toggle`

### JavaScript
- **Datei**: `assets/dashboard.js`
- **Funktionen**: AJAX Toggle, Notifications, Loading States
- **Events**: Change-Handler für Toggle Switches

### CSS
- **Datei**: `assets/dashboard.css`
- **Features**: Moderne Toggle Switches, Dark Theme Support
- **Responsive**: Mobile-friendly Design

### Fragment
- **Datei**: `fragments/toggle_buttons.php`
- **Zweck**: Wiederverwendbare Toggle Button Komponente
- **Parameter**: Layout, Größe, welche Buttons anzeigen

## Verwendung

### Dashboard
Die Toggle Buttons erscheinen automatisch im Dashboard für Benutzer mit entsprechenden Berechtigungen.

### Fragment in anderen Seiten verwenden
```php
$fragment = new rex_fragment();
$fragment->setVar('layout', 'vertical'); // oder 'horizontal'
$fragment->setVar('size', 'compact'); // oder 'normal'
$fragment->setVar('show_frontend', true);
$fragment->setVar('show_backend', true);
$fragment->setVar('show_domain_mapping', true);
echo $fragment->parse('toggle_buttons.php');
```

## Sprachunterstützung

### Deutsche Übersetzungen
```
upkeep[domain_mapping] = Domain-Redirects
upkeep_quick_toggle_frontend = Frontend Wartung umschalten
upkeep_toggle_success = Einstellung erfolgreich geändert
# ... weitere
```

### Englische Übersetzungen
```
upkeep[domain_mapping] = Domain Redirects
upkeep_quick_toggle_frontend = Toggle frontend maintenance
upkeep_toggle_success = Setting changed successfully
# ... weitere
```

## Sicherheit

- Alle Toggle-Aktionen prüfen Berechtigungen
- CSRF-Schutz durch REDAXO API
- Cache wird nach Änderungen geleert
- Fehlerbehandlung mit Rollback

## Browser-Kompatibilität

- Moderne Browser (Chrome, Firefox, Safari, Edge)
- CSS Grid/Flexbox Support erforderlich
- JavaScript ES5+ erforderlich
- Responsive Design für Mobile

## Changelog

### Version 1.6.0+
- ✅ Neue Berechtigung `upkeep[domain_mapping]`
- ✅ Quick Toggle Buttons im Dashboard
- ✅ AJAX API für Toggle-Funktionen
- ✅ Responsive Design
- ✅ Dark Theme Support
- ✅ Accessibility Features
