# Upkeep der KLXM Wartungsmodus für REDAXO 5

Ein modernes, schlankes AddOn zum Sperren des REDAXO Frontends und/oder Backends während Wartungsarbeiten.

## Features

- **Frontend-Sperre** mit eleganter und anpassbarer Wartungsseite
- **Backend-Sperre** für Redakteure (Admins haben immer Zugriff)
- **Domain-spezifische Sperren** für Multidomains mit YRewrite
- **Passwort-Bypass** zum Testen des Frontends im Wartungsmodus
- **Automatischer Zugang** für angemeldete Benutzer (konfigurierbar)
- **IP-Whitelist** mit einfacher Übernahme der aktuellen IP-Adresse
- **Konfigurierbare HTTP-Statuscodes** (503, 403, 307) mit Retry-After Header
- **Konsolen-Befehle** für Remote-Management

## Installation

1. Das AddOn über den REDAXO Installer installieren oder von GitHub herunterladen und installieren.
2. Konfigurieren Sie die Einstellungen über das REDAXO-Backend.

## Konfiguration

### Frontend-Wartungsmodus

Im Tab "Frontend" können Sie:
- Den Wartungsmodus aktivieren oder deaktivieren
- Den Titel und die Nachricht für die Wartungsseite anpassen
- Ein Passwort für den Testzugang festlegen
- Festlegen, ob angemeldete Benutzer Zugriff haben sollen
- IP-Adressen hinzufügen, die immer Zugriff haben
- Den HTTP-Statuscode (503, 403, 307) und Retry-After Header konfigurieren

### Backend-Wartungsmodus

Im Tab "Backend" können Sie:
- Den Wartungsmodus für das Backend aktivieren oder deaktivieren (sperrt alle Benutzer außer Administratoren)

### Domain-Einstellungen (nur bei YRewrite)

Wenn YRewrite installiert ist, können Sie im Tab "Domains":
- Den Wartungsmodus für einzelne Domains aktivieren oder deaktivieren

## Anpassen der Wartungsseite

Sie können die Wartungsseite anpassen, indem Sie ein eigenes Fragment erstellen:

1. Erstellen Sie den Ordner `fragments/upkeep` in Ihrem Project-AddOn
2. Kopieren Sie die Datei `fragments/upkeep/frontend.php` aus dem Upkeep-AddOn dorthin
3. Passen Sie den Inhalt der Datei nach Ihren Wünschen an

## Konsolen-Befehle

Sie können den Wartungsmodus auch über die Konsole aktivieren oder deaktivieren:

```bash
# Frontend-Wartungsmodus aktivieren
php redaxo/bin/console upkeep:mode frontend on

# Frontend-Wartungsmodus deaktivieren
php redaxo/bin/console upkeep:mode frontend off

# Backend-Wartungsmodus aktivieren
php redaxo/bin/console upkeep:mode backend on

# Backend-Wartungsmodus deaktivieren
php redaxo/bin/console upkeep:mode backend off
```

## Extension Points

- `UPKEEP_ALLOWED_PATHS`: Hier können Sie Pfade definieren, die vom Wartungsmodus ausgenommen werden sollen (z.B. für APIs oder bestimmte Medien)

## Autorenschaft

- KLXM Crossmedia

## Lizenz

MIT License - siehe LICENSE.md

## Support

Bei Fragen oder Problemen erstellen Sie bitte ein Issue auf GitHub oder besuchen Sie das REDAXO-Forum.
