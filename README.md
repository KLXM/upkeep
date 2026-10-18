# Upkeep

Wartung, Schutz und Überblick für REDAXO-Websites – in einem AddOn, übersichtlich und einfach einzustellen.

- **Übersicht für alle:** Admins, Redakteure und Kunden sehen dieselbe Startseite – mit den Kacheln, die zu ihrer Rolle passen.
- **Wartung:** Website oder Backend sperren, mit Passwort, freigegebenen IPs oder geheimem Vorschau-Link. Auch je Domain (YRewrite).
- **Schutz (IPS):** erkennt Angriffe und sperrt auffällige Adressen. Gesperrte Menschen können sich auf dem Sperrbildschirm selbst freischalten (ALTCHA).
- **Formularschutz:** schützt YForm-Formulare im Frontend vor Spam, Bots und KI-Agenten – ohne zusätzliches Feld und ohne Captcha.
- **E-Mail-Schutz:** prüft E-Mails, die über die Website verschickt werden.
- **Weiterleitungen:** Domains und Adressen umleiten.
- **Empfehlungen:** ruhige Hinweise zu Sicherheit und Betrieb, geprüft auf Knopfdruck oder per Cronjob.
- **Speicher:** wie in macOS – Bilder, Videos, Dokumente, Datenbank, Cache, Backups auf einen Blick.
- **Berichte und Schnittstellen:** E-Mail-Berichte, Wartungs-API, System-Health-API.

Voraussetzungen: REDAXO ab 5.18.1, PHP ab 8.2. Optional: YForm (Formularschutz), YRewrite (Wartung je Domain), PHPMailer (E-Mail-Schutz, Berichte), Cronjob (automatische Aufgaben).

## Installation und Update

Installation über den Installer im Backend oder per Konsole:

```bash
php redaxo/bin/console install:download upkeep 3.0.0
php redaxo/bin/console package:install upkeep
```

Bei der Neuinstallation wird ein zufälliges Passwort für die Wartungsseite erzeugt und einmal angezeigt. Ihre eigene IP-Adresse wird freigegeben.

### Update von 2.x

Das Update übernimmt alle Einstellungen, Tabellen und Daten automatisch. Nach dem Update zeigt die Übersicht Admins einmal, was sich geändert hat.

| Was | Verhalten in 3.0 |
|---|---|
| Passwort der Wartungsseite | wird nur noch als Hash gespeichert; das bisherige Passwort gilt weiter |
| Umgehungs-Link | braucht jetzt einen geheimen Wert: `?access=<geheim>`. Alte Links wie `?access=1` funktionieren nicht mehr. Den neuen Link finden Sie unter Einstellungen > Wartung. |
| Rechte | `upkeep[frontend]` wird zu `upkeep[maintenance]`, `upkeep[security]` zu `upkeep[ips]`, `upkeep[forms]`, `upkeep[advisor]` und `upkeep[reporting]`. Bestehende Rollen werden angepasst. |
| Menü-Schalter `*_enabled` | entfallen. Je Funktion gibt es einen Schalter unter Einstellungen > Allgemein; ausgeschaltet heißt jetzt wirklich aus. |
| Captcha auf dem Sperrbildschirm | ersetzt durch ALTCHA (ohne Cookies, ohne Fremddienst). `ips_captcha_trust_duration` wird zu `ips_unlock_hours`. |
| IP-Erkennung | nutzt nur noch `REMOTE_ADDR`. Hinter Load-Balancer, CDN oder Reverse-Proxy tragen Sie dessen Adressen unter Einstellungen > Allgemein > Vertrauenswürdige Proxys ein. |
| APIs | Token und Schlüssel bevorzugt im Header; Schalt-Aktionen der Wartungs-API nur per POST; die System-Health-API braucht immer einen Schlüssel. |

## Bedienung

### Übersicht

Die Startseite zeigt oben, ob die Website online oder im Wartungsmodus ist. Wer das Recht `upkeep[maintenance]` hat, schaltet die Wartung direkt dort ein und aus. Darunter folgen Kacheln für Schutz, Formulare, E-Mail-Schutz, Empfehlungen, Weiterleitungen und Speicher – jeweils nur mit dem passenden Recht. Admins sehen zusätzlich Systemangaben. Ein Ansprechpartner (Einstellungen > Allgemein) erscheint für alle Benutzer.

Die Übersicht prüft und berechnet nichts Aufwendiges: Alle Zahlen kommen aus Zwischenspeichern.

### Einstellungen

Alle Einstellungen liegen an einer Stelle (Upkeep > Einstellungen, nur Admins) – aufgebaut wie die Systemeinstellungen von macOS:

| Bereich | Inhalt |
|---|---|
| Allgemein | Funktionen ein- und ausschalten, Ansprechpartner, vertrauenswürdige Proxys |
| Wartung | Zugang während der Wartung, Passwort, Umgehungs-Link, Statuscode, Texte der Wartungsseite je Sprache |
| Weiterleitungen | Schalter, Verwaltung der Regeln |
| Schutz (IPS) | Nur beobachten, Selbst-Entsperrung, Anfragen begrenzen, Protokoll, Bereinigung, Länder-Datenbank |
| Formularschutz | Schutzstufe, Prüfungen, Meldung, Ausnahmen, Schwellen |
| E-Mail-Schutz | Prüfungen, Versandgrenzen, Absender, Benachrichtigung, Bereinigung |
| Empfehlungen | Schalter, Dauer für ausgeblendete Empfehlungen |
| Berichte | Empfänger, Versandart, Anlässe, Test-E-Mail |
| Schnittstellen | Token der Wartungs-API, Schlüssel der System-Health-API |

### Wartung

- **Website (Frontend):** Besucher sehen die Wartungsseite (HTTP 503 mit `Retry-After`, wählbar 403). Zugang behalten: angemeldete Backend-Benutzer (abschaltbar), freigegebene IP-Adressen und Netze, Besucher mit dem Passwort, Aufrufe mit dem geheimen Umgehungs-Link.
- **Backend:** Nur Admins können sich anmelden. Admins, die als Redakteur angemeldet sind, sehen einen Hinweis.
- **Domains:** Mit YRewrite einzelne Domains oder alle sperren.
- Die Wartungsseite ist mehrsprachig; Texte je Sprache pflegen Sie unter Einstellungen > Wartung.
- Das Passwort lässt nur fünf Fehlversuche je IP (bei IPv6 je /64-Netz) in 15 Minuten zu und wird nur per POST angenommen. Nach 50 Fehlversuchen insgesamt in 15 Minuten nimmt die Seite vorübergehend gar kein Passwort an.
- Freigegebene IP-Adressen der Wartung umgehen auch die Prüfungen des IPS (sie gelten wie die Positivliste). Tragen Sie dort nur Adressen ein, denen Sie voll vertrauen.

### Schutz (IPS)

Das IPS prüft jede Anfrage im Frontend auf bekannte Angriffsmuster (SQL-Injection, Pfad-Manipulation, Zugriffe auf Schwachstellen anderer Systeme usw.). Je nach Schwere wird die Anfrage protokolliert oder die Adresse gesperrt. „Nur beobachten“ protokolliert, ohne zu sperren.

- **Sperrstufen:** Hoch: 1 Stunde. Kritisch: 24 Stunden. Dauerhaft erst, wenn dieselbe Adresse innerhalb von 7 Tagen dreimal kritisch auffällt – ein einzelner Treffer sperrt nie dauerhaft. Mittel: ab drei Treffern in 24 Stunden 30 Minuten.
- **Anfragen fremder Websites:** Bindet eine andere Website eine Adresse Ihrer Seite ein (Bild, Skript, Stylesheet), schickt der Browser des Besuchers die Anfrage, nicht der Besucher selbst. Solche Anfragen (Kopfzeile `Sec-Fetch-Site: cross-site`, kein Seitenaufruf, kein POST) werden nur protokolliert und nicht an fail2ban gegeben. So kann niemand fremde Besucher per eingebettetem Bild sperren lassen. Weil sich diese Kopfzeilen fälschen lassen, sperren erst viele solcher Treffer in kurzer Zeit (20 in 10 Minuten) für eine Stunde – selbst aufhebbar.
- **Ereignisse, gesperrte IPs, Positivliste, Muster:** unter Upkeep > Schutz. Eigene Muster werden beim Speichern geprüft, auch auf zu aufwendige Ausdrücke, und brauchen mindestens 3 Zeichen. Bereiche auf der Positivliste dürfen höchstens /16 (IPv4) bzw. /32 (IPv6) groß sein.
- **Sperrbildschirm:** zeigt den Grund (allgemein), die eigene IP, den Zeitpunkt und den Kontakt. Das Widget braucht HTTPS.
- **Fehlertolerant:** Fehlt eine Tabelle oder tritt ein Fehler auf, bleibt die Website erreichbar; der Fehler steht im System-Log.
- **Zeit:** Alle Ablaufzeiten werden mit der Uhr von PHP geschrieben und verglichen. Unterschiedliche Zeitzonen von PHP und Datenbank verlängern oder verkürzen Sperren nicht mehr.

#### Was erkannt wird

- **Bekannte Angriffsmuster in der Adresse:** SQL-Injection, Pfad-Manipulation, Einschleusen von Code und Vorlagen (z. B. `{{7*7}}`), PHP-Stream-Wrapper, Nullbytes, Zugriffe auf Cloud-Metadaten (SSRF).
- **Suche nach Lücken anderer Systeme:** WordPress, TYPO3, Drupal, Joomla, Laravel, PHPUnit, ThinkPHP, Spring Boot, Router und VPN-Geräte, Outlook Web Access.
- **Suche nach vertraulichen Dateien:** `.env`, `.git`, Zugangsdaten (`.aws`, `.ssh`, `.htpasswd`), Editor-Einstellungen, Sicherungen und Datenbank-Exporte.
- **Scanner und Pentest-Werkzeuge** am User-Agent (z. B. sqlmap, Nikto, Nuclei, ffuf, WPScan, Acunetix), nur als ganzes Wort. Allgemeine Bibliotheken wie curl oder python-requests werden nicht gesperrt; fällt eine Anfrage von Go-http-client, python-requests, python-urllib, libwww-perl oder aiohttp zusätzlich mit einem mittleren Treffer auf, gilt sie als „hoch“.
- **Angriffe über Kopfzeilen und Cookies:** Log4Shell (auch verschleiert), Shellshock, Spring4Shell und Rückruf-Adressen von Scannern (OAST, z. B. `oast.pro`, `interact.sh`, `oastify.com`) in User-Agent, Referer, X-Forwarded-For, X-Api-Version, Cookies und weiteren Kopfzeilen; eingeschleuste Kopfzeilen (CRLF) in der Adresse.
- **Formulare im Frontend:** Der Inhalt von POST-Anfragen (höchstens 64 KB) wird nur auf eindeutige Signaturen geprüft (Log4Shell, Spring4Shell, Rückruf-Adressen, `php://filter`), nicht auf SQL-Wörter. Das Backend wird nicht geprüft.
- **Ungewöhnliche HTTP-Methoden:** TRACE, TRACK, DEBUG und CONNECT (hoch), WebDAV-Methoden wie PROPFIND (mittel; Office und der Windows-Explorer sind ausgenommen). GET, POST, HEAD, OPTIONS, PUT, PATCH und DELETE bleiben unberührt.
- **Verzeichnis-Suche:** Viele Fehlerseiten (404) von einer Adresse in kurzer Zeit (Standard: 30 in 60 Sekunden) sperren eine Stunde, selbst aufhebbar. Bilder, Stylesheets, Skripte, Medien, eingebettete Anfragen, Anfragen fremder Seiten, angemeldete Backend-Nutzer und verifizierte Suchmaschinen zählen nicht mit. Einstellbar unter Einstellungen > Schutz (IPS).
- **Ohne User-Agent:** wird nur protokolliert (niedrig), nie gesperrt. Niedrige Treffer zählen nicht zu den „wiederholten Verstößen“.

Referer und Formularinhalte kann eine fremde Website bestimmen (Link oder Formular auf ihrer Seite). Treffer dort werden bei Anfragen von fremden Seiten (`Sec-Fetch-Site: cross-site`) nur protokolliert. Die Standardmuster stehen unter Schutz > Muster und lassen sich anpassen oder abschalten; neue Muster aus Updates werden ergänzt, ohne Ihre Änderungen zu überschreiben.

#### Statistik

Unter Schutz > Statistik (nur Admins) stehen die Zahlen für 24 Stunden, 7, 30 oder 90 Tage: Treffer gesamt, Sperren (zeitweise/dauerhaft), aktuell gesperrte IPs, Selbst-Entsperrungen, nur protokollierte Treffer (auch von fremden Seiten) und abgewiesene Formulare. Dazu ein Verlauf pro Tag bzw. Stunde nach Schweregrad (auch als Tabelle), die Aufschlüsselung nach Art, Schweregrad, Ergebnis und Herkunft der aktuellen Sperren sowie die zehn auffälligsten Adressen. Gezählt werden Treffer (zusammengefasste Ereignisse zählen mehrfach); jede Zeile führt zu den passend gefilterten Ereignissen.

#### Selbst entsperren – und weiter überwacht

Entsperren heißt nicht, dass eine Adresse nicht mehr überwacht wird.

- Selbst entsperren kann sich nur, wer gerade eine eigene automatische, zeitlich begrenzte Sperre hat. Ohne Sperre gibt es keine Rechenaufgabe und keine Entsperrung.
- Nur die eigene IP, höchstens `ips_unlock_max`-mal in 24 Stunden (bei IPv6 je /64-Netz); `0` schaltet die Selbst-Entsperrung aus. Ist das Limit erreicht, zeigt der Sperrbildschirm keine Rechenaufgabe mehr.
- Nicht selbst aufheben lassen sich manuelle Sperren, dauerhafte Sperren und Sperren ganzer Bereiche.
- Nach dem Entsperren wird die Adresse für `ips_unlock_hours` nur **markiert**. Sie kommt **nicht** auf die Positivliste und wird weiter vollständig geprüft. Jede neue Sperre in dieser Zeit (Muster, Scanner, Häufung, Verzeichnis-Suche, Anfragen-Limit, Formular- und E-Mail-Schutz) lässt sich nicht noch einmal selbst aufheben.
- Die Markierungen stehen unter Schutz > Positivliste in einer eigenen Liste „Selbst entsperrt – weiter überwacht“.
- Einträge aus 3.0.0/3.0.1 (Kategorie `captcha_verified_temp`) werden beim Update zu Markierungen.

#### fail2ban

Sperren können in eine Logdatei im REDAXO-Logordner geschrieben werden (Einstellungen > Schutz). Eine Zeile sieht so aus:

```text
2026-10-18 12:00:00 [REDAXO-IPS] HIGH threat from 203.0.113.7: "suspicious_user_agent" (URI: "/", Pattern: "sqlmap", Action: temporary_block)
```

URI, Muster und Typ stehen in Anführungszeichen; Steuerzeichen, Anführungszeichen und Nicht-ASCII-Zeichen sind maskiert. Verankern Sie den `failregex` trotzdem auf den Zeilenanfang, damit nur die echte Adresse direkt hinter `threat from` zählt:

```ini
[Definition]
failregex = ^(?:\S+ \S+ )?\s*\[REDAXO-IPS\] (?:CRITICAL|HIGH) threat from <HOST>: "
datepattern = {^LN-BEG}%%Y-%%m-%%d %%H:%%M:%%S
```

### Formularschutz (YForm)

Upkeep hängt sich automatisch in alle YForm-Formulare im Frontend ein. Sie müssen kein Feld anlegen; Formulare im Backend und Anmeldeformulare (`ycom_auth`) bleiben unberührt. Für Besucher ändert sich nichts – es gibt kein Captcha.

Geprüft wird unsichtbar und mit Punkten statt fester Regeln:

- Falle (Feld, das nur Bots ausfüllen), signierter Zeitstempel und Mindestzeit fürs Ausfüllen
- unsichtbare Rechenaufgabe (ALTCHA-Proof-of-Work, im Hintergrund vom Browser gelöst; ohne JavaScript nur Punktabzug)
- Verhalten beim Ausfüllen (Tippen, Zeiger, Fokus, nur eingefügt, ferngesteuerter Browser)
- KI-Agenten und Bots (Header `Signature-Agent` nach Web Bot Auth, bekannte Kennungen wie GPTBot, ClaudeBot, PerplexityBot, Headless-Browser, Skript-Werkzeuge)
- Inhalt (Anzahl Links, BBCode, Spam-Wörter aus dem E-Mail-Schutz, optional fremde Schriftsysteme)
- Einsendungen je IP und Zeitfenster

Erreicht eine Einsendung die Schwelle, zeigt YForm eine neutrale Meldung und führt keine Aktionen aus: keine E-Mail, kein Speichern. Eindeutiger Spam wird dem IPS gemeldet. Die Stufe „Streng“ weist zusätzlich KI-Agenten und ferngesteuerte Browser ab.

Einzelnes Formular ausnehmen:

```php
// im Formular-Code
$yform->setObjectparams('upkeep_spam_protection', 0);
```

```text
// in der Formular-Definition
objparams|upkeep_spam_protection|0
```

Oder unter Einstellungen > Formularschutz > Ausgenommene Formulare (Formularnamen). Abgewiesene Einsendungen sehen Sie unter Upkeep > Schutz > Formulare.

### E-Mail-Schutz

Prüft E-Mails, die im Frontend über PHPMailer verschickt werden: Spam-Wörter, Sperrliste (E-Mail, Domain, IP), Muster gegen Code- und Header-Injection, Versandgrenzen je IP. Geprüft werden nur Inhalte, die aus Besucher-Eingaben stammen – nicht die eigenen E-Mail-Vorlagen. Blockierte E-Mails werden nicht versendet (`send()` liefert `false`), die Seite läuft normal weiter. Listen und Ereignisse: Upkeep > Schutz > E-Mail.

### Empfehlungen

Die Empfehlungen prüfen Live-Modus, PHP-Einstellungen, Versionen, Dateirechte, Datenbank, E-Mail-Versand, HTTPS/HSTS, CSP, Sitzungen und mehr. Geprüft wird nur auf Knopfdruck („Jetzt prüfen“), per Cronjob „Upkeep: Empfehlungen aktualisieren“ oder per Konsole – nie beim bloßen Aufruf einer Seite. Offene Punkte stehen mit Priorität und Begründung in einer Liste. Admins können sie ausblenden (sie erscheinen nach der eingestellten Zeit wieder) oder einzelne Einstellungen direkt übernehmen. Der Bericht lässt sich als JSON herunterladen.

### Speicher

Zeigt den Speicherverbrauch der Website als Balken mit Legende: Bilder, Videos, Dokumente, Audio, sonstige Medien, Media-Manager-Cache, Datenbank, Backups, Logs, Cache, System und AddOns – dazu freier Platz (wenn der Server ihn meldet), die größten Dateien und die größten Tabellen. Redakteure sehen die Übersicht, Admins berechnen sie neu und leeren den Media-Manager-Cache. Berechnet wird nur auf Knopfdruck, per Cronjob „Upkeep: Speicherbelegung berechnen“ oder per Konsole.

## Rechte

| Recht | Bereich |
|---|---|
| `upkeep[]` | Übersicht und Speicher |
| `upkeep[maintenance]` | Wartung ein- und ausschalten |
| `upkeep[domains]` | Wartung je Domain |
| `upkeep[domain_mapping]` | Weiterleitungen |
| `upkeep[ips]` | Schutz: Ereignisse, gesperrte IPs, Positivliste, Muster |
| `upkeep[forms]` | Formularschutz einsehen |
| `upkeep[mail_security]` | E-Mail-Schutz |
| `upkeep[advisor]` | Empfehlungen einsehen und prüfen |
| `upkeep[reporting]` | Berichte |

Einstellungen, Backend-Sperre, die Schutz-Statistik und das Übernehmen von Empfehlungen sind Admins vorbehalten.

## Konsole und Cronjobs

```bash
php redaxo/bin/console upkeep:mode frontend on        # frontend|backend, on|off
php redaxo/bin/console upkeep:security:scan           # Empfehlungen aktualisieren
php redaxo/bin/console upkeep:storage                 # Speicherübersicht berechnen (--json)
php redaxo/bin/console upkeep:ips:cleanup             # alte IPS-Daten bereinigen
php redaxo/bin/console upkeep:mail-reporting:send-bundle --interval=3600
```

Cronjob-Typen (AddOn Cronjob): „Upkeep IPS: Bereinigung veralteter Sicherheitsdaten“ (optional mit Aktualisierung der Länder-Datenbank), „Upkeep: Empfehlungen aktualisieren“, „Upkeep: Speicherbelegung berechnen“.

## Schnittstellen

Alle Schnittstellen antworten mit JSON. Token und Schlüssel werden mit konstanter Laufzeit verglichen, Fehlversuche werden begrenzt (HTTP 429; bei IPv6 je /64-Netz).

### Wartungs-API

Token unter Einstellungen > Schnittstellen.

```bash
# Status (GET oder POST)
curl -H "Authorization: Bearer <token>" "https://example.org/index.php?rex-api-call=upkeep&action=status"

# Schalten (nur POST): set_frontend, set_backend, set_all_domains, set_domain (mit domain=…)
curl -X POST -H "Authorization: Bearer <token>" -d "action=set_frontend&status=1" "https://example.org/index.php?rex-api-call=upkeep"
```

Alternativ Header `X-Upkeep-Token`. Der Parameter `token` in der Adresse funktioniert noch, ist aber **veraltet** und wird in einer späteren Version entfernt: Adressen mit Token landen in Server-Logs, Verläufen und Referrern. Bitte auf einen der Header umstellen.

### System-Health-API

Einschalten und Schlüssel unter Einstellungen > Schnittstellen. Ohne gültigen Schlüssel antwortet die Schnittstelle nur mit 403.

```bash
curl -H "Authorization: Bearer <schlüssel>" "https://example.org/index.php?rex-api-call=upkeep_system_health"
curl -H "X-Upkeep-Health-Key: <schlüssel>" "https://example.org/index.php?rex-api-call=upkeep_system_health&detailed=1"
curl -H "Authorization: Bearer <schlüssel>" "https://example.org/index.php?rex-api-call=upkeep_system_health&format=text"
```

Datenbank-Zugangsdaten, E-Mail-Adressen und Server-Software werden nicht ausgegeben.

### E-Mail-Schutz-API

`index.php?rex-api-call=upkeep_mail_security&endpoint=…` mit dem Token der Wartungs-API (`Authorization: Bearer`). Endpunkte und Beispiele: [API_MAIL_SECURITY.md](API_MAIL_SECURITY.md).

## Für Entwickler

### Extension Points

| Name | Wann | Inhalt |
|---|---|---|
| `UPKEEP_IPS_THREAT_DETECTED` | IPS erkennt eine Bedrohung | Daten des Ereignisses (IP, URI, Typ, Schwere, Muster) |
| `UPKEEP_MAINTENANCE_CHANGED` | Wartung wird ein- oder ausgeschaltet | Bereich, Status, Auslöser |
| `UPKEEP_SECURITY_SCAN_COMPLETED` | Empfehlungen wurden geprüft | vollständiges Prüfergebnis |
| `UPKEEP_FORM_SPAM_REJECTED` | Formularschutz weist eine Einsendung ab | Formular, Gründe, Punkte |
| `UPKEEP_ALLOWED_PATHS` | Wartung im Frontend | Liste von Pfaden, die trotz Wartung erreichbar bleiben |
| `UPKEEP_IPS_SCANNER_AGENTS` | IPS prüft den User-Agent | Liste der Scanner-Kennungen (ganze Wörter, ohne Groß-/Kleinschreibung) zum Ergänzen oder Entfernen |

```php
rex_extension::register('UPKEEP_ALLOWED_PATHS', static function (rex_extension_point $ep) {
    $paths = $ep->getSubject();
    $paths[] = '/api/'; // Pfad-Präfix an Pfadgrenzen, relativ zur Installation (/api gibt /api/… frei, nicht /api-x)
    return $paths;
});
```

Scanner-Kennungen ergänzen oder entfernen (z. B. in der `boot.php` des project-AddOns, das vor upkeep geladen wird). Für einen eigenen, erlaubten Scanner ist meist die Positivliste die bessere Wahl:

```php
rex_extension::register('UPKEEP_IPS_SCANNER_AGENTS', static function (rex_extension_point $ep) {
    $agents = $ep->getSubject();
    $agents[] = 'mein-scanner';                                 // ergänzen (mindestens 3 Zeichen)
    return array_values(array_diff($agents, ['qualys']));       // entfernen
});
```

### Klassen (Auswahl)

- `KLXM\Upkeep\Upkeep::setMaintenance('frontend'|'backend'|'all_domains'|'domain:<name>', bool $active, string $source)`
- `KLXM\Upkeep\ClientIp::get()` – Client-IP unter Berücksichtigung der vertrauenswürdigen Proxys
- `KLXM\Upkeep\IntrusionPrevention::reportExternalThreat(string $type, string $severity, string $details, ?string $ip = null)` – eigene Ereignisse an das IPS melden
- `KLXM\Upkeep\FormProtection::getStats(int $days)` / `getRecent(int $limit)`
- `KLXM\Upkeep\Storage::getReport()` / `refresh()`
- `KLXM\Upkeep\SecurityAdvisor::getCachedResults()` / `getRecommendations()`

### Tabellen

`rex_upkeep_domain_mapping`, `rex_upkeep_ips_blocked_ips`, `rex_upkeep_ips_threat_log`, `rex_upkeep_ips_custom_patterns`, `rex_upkeep_ips_default_patterns`, `rex_upkeep_ips_rate_limit`, `rex_upkeep_ips_positivliste`, `rex_upkeep_mail_rate_limit`, `rex_upkeep_mail_badwords`, `rex_upkeep_mail_blocklist`, `rex_upkeep_mail_threat_log`, `rex_upkeep_mail_default_patterns`, `rex_upkeep_form_log`.

Kleine Zähler und Zwischenspeicher (Anmeldeversuche, ALTCHA, Speicherübersicht) liegen als Dateien im Datenordner des AddOns, nicht in `rex_config`.

## Weitere Dokumentation

- [Wartung](MAINTENANCE.md)
- [E-Mail-Schutz](MAIL_SECURITY.md)
- [Empfehlungen](SECURITY_ADVISOR.md)
- [E-Mail-Schutz-API](API_MAIL_SECURITY.md)
- [Änderungen](CHANGELOG.md)

## Lizenz

MIT – siehe [LICENSE](LICENSE). Entwickelt von KLXM Crossmedia.

ALTCHA (MIT) ist im Ordner `assets/vendor/altcha` enthalten.
