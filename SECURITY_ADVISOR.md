# Empfehlungen

Die Empfehlungen (früher Security Advisor) prüfen Ihre REDAXO-Installation auf Sicherheit und Betrieb und zeigen offene Punkte als ruhige Liste mit Priorität und Begründung. Sie finden sie unter Upkeep > Empfehlungen (Recht `upkeep[advisor]`). Ein- und ausgeschaltet werden sie unter Einstellungen > Empfehlungen.

## Wann geprüft wird

Die Seite prüft nie von selbst. Ein Scan läuft nur

- auf Knopfdruck („Jetzt prüfen“) auf der Seite Empfehlungen,
- als Cronjob vom Typ „Upkeep: Empfehlungen aktualisieren“ (AddOn Cronjob),
- per Konsole.

Das Ergebnis wird zwischengespeichert (`advisor_results`, Zeitpunkt in `advisor_last_check`). Seiten und die Übersicht zeigen nur diesen Stand; wann er erstellt wurde, steht oben auf der Seite.

```bash
php redaxo/bin/console upkeep:security:scan                    # Tabelle
php redaxo/bin/console upkeep:security:scan --format=summary
php redaxo/bin/console upkeep:security:scan --format=json --output-file=scan.json
php redaxo/bin/console upkeep:security:scan --filter=error --silent   # ab Symfony Console 7.2 die globale Option: keine Ausgabe
```

Mit `--filter` (`error`, `warning`, `success`, `all`) begrenzen Sie die Ausgabe. Der Rückgabewert ist `0` ohne Auffälligkeit, `1` bei Warnungen und `2` bei kritischen Problemen, so lässt sich der Befehl in Skripten und Monitoring auswerten.

## Was geprüft wird

- **REDAXO:** Live-Modus, Debug-Modus, Version und verfügbare Updates, Produktivbetrieb
- **Server:** PHP-Einstellungen und -Version, Webserver-Version, Datei- und Verzeichnisrechte
- **PHP-Sicherheitslücken:** ob die PHP-Version von einer bekannten Lücke in PHP selbst betroffen ist (z. B. [CVE-2026-109618/109619](https://www.php.net/archive/2026.php#2026-10-21-5), gefixt in 8.2.35, 8.3.36, 8.4.27, 8.5.12; 8.1 und älter ohne Fix). Solange die Version betroffen ist, zeigt der Punkt zusätzlich, welche Übergangsmaßnahmen noch fehlen. Abwehren kann Upkeep solche Lücken nicht: Sie greifen teils, bevor Code der Website läuft, und die Maßnahmen wirken nur in php.ini, FPM-Pool oder Serverkonfiguration. Spielt der Hoster den Fix ein, ohne die Versionsnummer zu ändern (Debian, Ubuntu, LTS-Anbieter), blenden Admins den Punkt aus. Konsole und Cronjob prüfen die PHP-Version der Kommandozeile, die von der Website abweichen kann.
- **Header:** `Server`, `X-Powered-By` und Sicherheits-Header. Dafür ruft Upkeep die eigene Startseite ab und liest deren Antwort-Header (Timeout wenige Sekunden). Ist die Seite nicht erreichbar, bleibt der Punkt als Hinweis stehen.
- **HTTPS:** Verschlüsselung für Frontend und Backend, HSTS
- **Content Security Policy** für das Backend
- **Sitzungen:** Cookie-Einstellungen
- **Datenbank und E-Mail-Versand:** Verbindung, Zugangsdaten, SMTP und Verschlüsselung (PHPMailer)
- **Benutzer:** Anzahl der Admins, Passwort-Richtlinien
- **Wartung:** ob die Wartung versehentlich eingeschaltet ist

## Die Liste

Offene Punkte stehen nach Priorität sortiert (hoch, mittel, niedrig), jeweils mit Beschreibung und konkreten Schritten. Erledigte Punkte sind eingeklappt.

- **Ausblenden:** Admins können einen Punkt für eine Anzahl Tage ausblenden (Dauer unter Einstellungen > Empfehlungen, Standard 30 Tage). Danach erscheint er wieder, solange er offen ist. Ausgeblendete Punkte lassen sich jederzeit zurückholen.
- **Direkt übernehmen:** Für vier Punkte bieten Admins einen Knopf an, der die Einstellung selbst setzt: Live-Modus, Content Security Policy, HSTS und Sitzungssicherheit. Live-Modus und HSTS fragen vorher nach, die `config.yml` wird vorher gesichert. Prüfen Sie danach Ihre Website.
- **Download:** Admins laden den letzten Bericht als JSON herunter.

## Ereignisse und Schnittstellen

Nach jedem Scan wird der Extension Point `UPKEEP_SECURITY_SCAN_COMPLETED` mit dem vollständigen Ergebnis ausgelöst:

```php
rex_extension::register('UPKEEP_SECURITY_SCAN_COMPLETED', static function (rex_extension_point $ep) {
    $results = $ep->getSubject();
    // $results['checks'], $results['timestamp'] …
});
```

Die Kennzahlen (Zeitpunkt, Bewertung, kritische Punkte und Warnungen) liefert auch die System-Health-API, siehe README. Für eigene Auswertungen:

```php
use KLXM\Upkeep\SecurityAdvisor;

$results = SecurityAdvisor::getCachedResults();            // null, wenn nie geprüft
$recommendations = (new SecurityAdvisor())->getRecommendations(); // open, hidden, passed, last_check
```

Berichte per E-Mail (Einstellungen > Berichte, Anlass „Empfehlungen“) informieren über neue Ergebnisse. Auch bei Sammelversand kommt eine Sofort-Mail, sobald ein kritischer Punkt neu offen ist (nicht ausgeblendet; erneut, wenn er behoben war und wiederkommt, oder bei einer weiteren PHP-Lücke). Beim ersten Scan nach dem Update meldet sie nur PHP-Lücken, bestehende Punkte stehen weiter im Sammelbericht. Damit das ohne Zutun passiert, den Cronjob „Upkeep: Empfehlungen aktualisieren“ täglich laufen lassen.

Weitere PHP-Lücken lassen sich über den Extension Point `UPKEEP_PHP_ADVISORIES` ergänzen (Aufbau siehe `KLXM\Upkeep\PhpAdvisories`).

## Fehlersuche

- **Es steht „noch nie geprüft“ da:** Starten Sie einen Scan mit „Jetzt prüfen“ oder richten Sie den Cronjob ein.
- **Header-Prüfung ohne Ergebnis:** Die Startseite muss vom Server selbst per HTTP(S) erreichbar sein. Hinter Authentifizierung oder bei gesperrtem Loopback schlägt der Abruf fehl.
- **Ein Knopf zum Übernehmen fehlt:** Er steht nur Admins zur Verfügung und nur, solange der Punkt offen ist.
- **Ein behobener Punkt steht weiter offen:** Die Liste zeigt den Stand des letzten Scans. Prüfen Sie erneut.
