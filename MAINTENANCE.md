# Wartung

Mit der Wartung sperren Sie die Website, das Backend oder einzelne Domains vorübergehend. Besucher sehen eine Wartungsseite, Sie und freigegebene Personen arbeiten weiter.

Zu finden unter Upkeep > Wartung (Reiter Status, Domains, Weiterleitungen) und Upkeep > Einstellungen > Wartung. Auf der Übersicht schalten Sie die Wartung mit dem Recht `upkeep[maintenance]` direkt ein und aus.

## Website (Frontend)

Ist die Wartung eingeschaltet, sehen Besucher die Wartungsseite mit HTTP 503 und `Retry-After` (wählbar: 403). Suchmaschinen erhalten so das richtige Signal. Zugang behalten:

- **Angemeldete Backend-Benutzer** (abschaltbar unter Einstellungen > Wartung > Zugang)
- **Freigegebene IP-Adressen und Netze** (eine pro Zeile oder durch Komma getrennt, CIDR erlaubt). Achtung: Diese Adressen umgehen auch die Prüfungen des IPS – tragen Sie nur Adressen ein, denen Sie voll vertrauen.
- **Besucher mit dem Passwort** der Wartungsseite
- **Aufrufe mit dem geheimen Umgehungs-Link**
- **Pfade**, die Sie per Extension Point freigeben (siehe unten)

Die Schnittstellen von Upkeep (Wartungs-API, System-Health-API, E-Mail-Schutz-API) bleiben erreichbar; sie prüfen ihre Zugangsdaten selbst.

### IP-Adressen

Die IP-Adresse stammt aus `REMOTE_ADDR`. Hinter Load-Balancer, CDN oder Reverse-Proxy tragen Sie dessen Adressen unter Einstellungen > Allgemein > Vertrauenswürdige Proxys ein; nur dann wird die Client-IP aus den Proxy-Headern übernommen. Neben dem Feld „Freigegebene IPs“ zeigt Upkeep Ihre aktuelle Adresse an.

### Passwort

Das Passwort setzen Sie unter Einstellungen > Wartung > Zugang. Es wird nur als Hash gespeichert und nie wieder angezeigt; ein leeres Feld lässt das bisherige Passwort unverändert. Die Wartungsseite nimmt das Passwort ausschließlich per POST an. Nach fünf Fehlversuchen je IP ist die Eingabe für 15 Minuten gesperrt.

### Umgehungs-Link

Unter Einstellungen > Wartung > Umgehung schalten Sie den Link ein. Er hat die Form:

```text
https://example.org/?<bypass_param_key>=<bypass_secret>
```

Der Parametername (Standard `access`) ist frei wählbar, der Wert ist ein geheimer, zufällig erzeugter Schlüssel. Nur diese Kombination schaltet frei; ein Aufruf wie `?access=1` genügt nicht. Den fertigen Link sehen Sie in den Einstellungen, dort erzeugen Sie bei Bedarf einen neuen Schlüssel. Der alte Link verliert dann seine Gültigkeit. Geben Sie den Link nur weiter, wenn Sie dem Empfänger vertrauen.

### Wartungsseite

Statuscode (503 oder 403) und `Retry-After` stellen Sie unter Einstellungen > Wartung > HTTP ein. Titel, Text und Beschriftungen pflegen Sie je Sprache unter „Texte“; Besucher wechseln die Sprache auf der Wartungsseite. Das Aussehen steuern die Fragmente `fragments/upkeep/frontend.php` (Frontend) und `backend.php` (Backend). Wie bei jedem REDAXO-Fragment überschreiben Sie diese in einem eigenen AddOn oder Projekt-AddOn mit gleichem Pfad, ohne das AddOn zu ändern.

## Backend

Bei Backend-Wartung können sich nur Admins anmelden. Alle anderen Benutzer sehen eine Wartungsmeldung. Angemeldete Admins, auch im Benutzerwechsel, arbeiten ungestört; das Frontend ist davon nicht betroffen.

## Domains

Mit YRewrite sperren Sie unter Wartung > Domains einzelne Domains oder alle auf einmal. Für gesperrte Domains gelten dieselben Zugangsregeln wie für das Frontend.

## Pfade freigeben

Der Extension Point `UPKEEP_ALLOWED_PATHS` gibt Pfade trotz Wartung frei. Verglichen wird der Pfad ohne Query als Präfix an Pfadgrenzen, relativ zur Installation (liegt REDAXO in einem Unterordner, lassen Sie ihn weg): `/media` gibt `/media` und `/media/…` frei, aber nicht `/media-x`.

```php
rex_extension::register('UPKEEP_ALLOWED_PATHS', static function (rex_extension_point $ep) {
    $paths = $ep->getSubject();
    $paths[] = '/api/';
    return $paths;
});
```

Registrieren Sie den Extension Point in der `boot.php` Ihres AddOns. Pfade mit `..` werden ignoriert.

## Wartung in eigenem Code

```php
use KLXM\Upkeep\Upkeep;

// Bereich: 'frontend', 'backend', 'all_domains' oder 'domain:<name>'
$changed = Upkeep::setMaintenance('frontend', true, 'deploy');
```

`setMaintenance()` liefert `true`, wenn sich der Status geändert hat, und löst dann den Extension Point `UPKEEP_MAINTENANCE_CHANGED` aus. Dessen Parameter: `type` (Bereich), `status`, `source`, `timestamp`, `user`, `ip` und `config`. Der dritte Parameter ist Ihre Quellenangabe (`backend`, `api`, `console` oder frei).

```php
rex_extension::register('UPKEEP_MAINTENANCE_CHANGED', static function (rex_extension_point $ep) {
    $p = $ep->getParams();
    rex_logger::factory()->info(sprintf('Wartung %s: %s', $p['type'], $p['status'] ? 'an' : 'aus'));
});
```

## Konsole

```bash
php redaxo/bin/console upkeep:mode frontend on    # frontend|backend, on|off
php redaxo/bin/console upkeep:mode backend off
```

Für geplante Wartungsfenster rufen Sie den Befehl aus einem Cronjob oder Deploy-Skript auf.

## Wartungs-API

Token und Beispiele: Einstellungen > Schnittstellen. Das Token wird bevorzugt als `Authorization: Bearer <token>` (oder `X-Upkeep-Token`) übergeben.

```bash
# Status (GET oder POST)
curl -H "Authorization: Bearer <token>" \
  "https://example.org/index.php?rex-api-call=upkeep&action=status"

# Schalten (nur POST)
curl -X POST -H "Authorization: Bearer <token>" \
  -d "action=set_frontend&status=1" \
  "https://example.org/index.php?rex-api-call=upkeep"
```

Schalt-Aktionen: `set_frontend`, `set_backend`, `set_all_domains` und `set_domain` (zusätzlich `domain=example.org`). Der Parameter `status` ist `1` oder `0`. Antworten sind JSON mit `success`. Der Status liefert `frontend_active`, `backend_active` und `all_domains_locked`. Nach 10 fehlgeschlagenen Anmeldungen je IP in 10 Minuten antwortet die API mit HTTP 429; Schalt-Aktionen per GET mit 405.

## Fehlersuche

- **Wartungsseite erscheint nicht:** Prüfen Sie, ob Sie als Backend-Benutzer angemeldet oder per IP freigegeben sind. Testen Sie in einem privaten Fenster. Seiten-Caches (Server, CDN) können die Wartungsseite verzögern.
- **Freigegebene IP greift nicht:** Hinter Proxy oder CDN fehlt meist der Eintrag unter Vertrauenswürdige Proxys.
- **Passwort wird nicht angenommen:** Nach fünf Fehlversuchen warten Sie 15 Minuten oder geben Ihre IP frei.
- **Backend gesperrt:** Setzen Sie die Wartung per Konsole zurück: `php redaxo/bin/console upkeep:mode backend off`.
