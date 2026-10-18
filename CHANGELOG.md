# Changelog

## 3.0.2 (2026-10-18)

Sicherheitsupdate. Danke für den Sicherheitshinweis aus der Community.

- Ausgeschaltete Bereiche (Weiterleitungen, Formularschutz, E-Mail-Schutz, Empfehlungen, Sperren/Positivliste/Muster bei ausgeschaltetem Schutz) verschwinden aus dem Menü; ein direkter Aufruf zeigt nur noch einen Hinweis und erlaubt keine Bearbeitung.
- Neu: Konsolenbefehl `upkeep:ips:unblock <ip> [--allow]` als Notausgang, falls ein Admin sich selbst ausgesperrt hat.
- IPS: Ein einzelner Treffer sperrt nicht mehr dauerhaft. Kritische Treffer sperren 24 Stunden; dauerhaft erst, wenn dieselbe Adresse innerhalb von 7 Tagen dreimal kritisch auffällt. Bisher konnten Dritte Besucher dauerhaft sperren lassen.
- IPS: Anfragen, die eine fremde Website im Browser des Besuchers auslöst (eingebettete Bilder, Skripte usw.), werden nur protokolliert und nicht an fail2ban gegeben. Erst viele solcher Treffer in kurzer Zeit (20 in 10 Minuten) sperren eine Stunde, selbst aufhebbar – sonst könnten Scanner sich mit gefälschten Kopfzeilen tarnen.
- IPS: Das Standardmuster „/*“ (SQL-Kommentar) war zu breit und wird auf einen vollständigen Kommentarblock eingeengt. Bestehende Installationen werden angepasst; von Ihnen geänderte Muster bleiben unverändert.
- IPS: Ablaufzeiten von Sperren und Positivliste werden mit derselben Uhr geschrieben und geprüft. Bei unterschiedlichen Zeitzonen von PHP und Datenbank dauerten Sperren bisher länger oder kürzer als eingestellt.
- IPS: Die Abstufung für „normale“ REDAXO-Adressen greift nicht mehr bei kodierten Zeichen in den Parametern und nie bei kritischen Treffern.
- Selbst-Entsperrung: Entsperren heißt nicht, dass die Adresse nicht mehr überwacht wird. Sie kommt nicht mehr auf die Positivliste, sondern wird nur markiert und weiter vollständig geprüft. Jede neue Sperre in dieser Zeit lässt sich nicht noch einmal selbst aufheben. Eine Rechenaufgabe zum Entsperren gibt es nur bei einer eigenen automatischen Sperre und nur, solange das Tageslimit nicht erreicht ist. Das Tageslimit lässt sich durch gleichzeitige Anfragen nicht mehr überschreiten. `ips_unlock_max = 0` schaltet die Selbst-Entsperrung aus.
- Selbst-Entsperrung: Bestehende Einträge aus 3.0.0/3.0.1 werden beim Update zu Markierungen. Die Positivliste zeigt sie in einer eigenen Liste „Selbst entsperrt – weiter überwacht“. Andere Einträge derselben Adresse (z. B. vom Admin) werden nicht mehr überschrieben.
- Zähler und Bremsen (Wartungspasswort, Selbst-Entsperrung, Rechenaufgaben, Schnittstellen, Formular- und E-Mail-Schutz) zählen IPv6-Adressen je /64-Netz. Das Wartungspasswort hat zusätzlich eine Obergrenze über alle Adressen (50 Fehlversuche in 15 Minuten).
- Positivliste: Bereiche größer als /16 (IPv4) bzw. /32 (IPv6) werden abgelehnt. Eigene Muster brauchen mindestens 3 Zeichen.
- fail2ban: URI, Muster und Typ stehen in der Logzeile maskiert in Anführungszeichen. Empfohlener, verankerter `failregex` in der README.
- Wartung: Freigegebene Pfade (`UPKEEP_ALLOWED_PATHS`) gelten nur noch an Pfadgrenzen (`/media` gibt nicht mehr `/media-x` frei).
- Wartungs-API: Das Token als Parameter in der Adresse ist veraltet (funktioniert noch); bitte den Header verwenden.
- Listen-Cache: Ein paralleler Request kann keinen veralteten Stand mehr in den Cache schreiben.
- Datenbank: Die Kategorie der Positivliste ist in Installation und Update einheitlich `varchar(50)`.
- Neu: Statistik zu Treffern, Sperren und Arten (Schutz > Statistik, nur Admins).
- IPS: Deutlich mehr Scanner und Pentest-Werkzeuge werden am User-Agent erkannt (z. B. Nuclei, ffuf, feroxbuster, WPScan, WhatWeb, zgrab, Commix). Erkannt wird nur das ganze Wort, damit ähnliche Namen nicht anschlagen. Allgemeine Bibliotheken wie curl bleiben erlaubt. Die Liste lässt sich über den Extension Point `UPKEEP_IPS_SCANNER_AGENTS` anpassen.
- IPS: Kopfzeilen und Cookies werden auf eindeutige Angriffe geprüft (Log4Shell, Shellshock, Spring4Shell, Rückruf-Adressen von Scannern), die Adresse zusätzlich auf eingeschleuste Kopfzeilen.
- IPS: POST-Anfragen im Frontend werden auf dieselben eindeutigen Signaturen geprüft (höchstens 64 KB, keine SQL-Wörter). Das Backend ist nicht betroffen.
- IPS: Ungewöhnliche HTTP-Methoden (TRACE, TRACK, DEBUG, CONNECT; WebDAV) werden erkannt.
- IPS: Neu „Verzeichnis-Suche“: Viele Fehlerseiten (404) in kurzer Zeit sperren eine Stunde, selbst aufhebbar. Standard an, Schwelle einstellbar (30 in 60 Sekunden). Bilder, Medien, eingebettete Anfragen und verifizierte Suchmaschinen zählen nicht.
- IPS: Neue Standardmuster für bekannte Lücken anderer Systeme (Laravel, PHPUnit, ThinkPHP, Spring Boot, Router, VPN-Geräte), Zugangsdaten und Editor-Dateien, Sicherungen und Datenbank-Exporte, Template-Injection, Stream-Wrapper, Nullbytes und Cloud-Metadaten. Beim Update werden nur fehlende Muster ergänzt.
- IPS: Anfragen ohne User-Agent werden nur protokolliert. Niedrige Treffer zählen nicht mehr zu den wiederholten Verstößen.
- Statistik und Ereignisse zeigen für alle Arten verständliche Bezeichnungen.
- IPS: Angemeldete Backend-Nutzer werden nie mehr gesperrt, im Frontend wie im Backend. Ihre Treffer werden nur protokolliert („Nur protokolliert (angemeldet)“, in Statistik und Ereignissen) und zählen weder als Verstoß noch zur Verzeichnis-Suche oder zum Anfragelimit. Eine Session wird dafür nur geprüft, wenn der Browser ein Session-Cookie schickt; gefälschte oder abgelaufene Sitzungen zählen nicht.
- IPS: Das Backend wird jetzt ebenfalls geprüft, solange niemand angemeldet ist (z. B. die Anmeldeseite). Gesperrte Adressen erreichen damit auch die Anmeldeseite nicht mehr. Für die eigenen festen Adressen bitte die Positivliste nutzen.
- IPS: Zu breite Standardmuster eingeengt, weil sie normale Adressen und Suchbegriffe trafen:
  - Pfade anderer Systeme (`/admin`, `/administrator`, `/modules/`, `/templates/`, `/plugins/`, `/themes/`, `/core/`, `/components/`, `/libraries/`, `/node/`, `/manager/`, `/dashboard/`, `/control/`, `/mysql/`, `/cpanel/`, `/webmail/`, `/user/login`, `/fileadmin/`, `/sites/default/`) zählen nur noch am Anfang des Pfads und sind „mittel“ statt „hoch“: Ein einzelner Aufruf sperrt nicht mehr, wiederholte schon. `/de/administration/` oder `/redaxo/` treffen nicht.
  - Shell-Befehle (`bash`, `sh`, `powershell`, `curl`, `wget`, `nc`, `cat`, `more`, `rm` …) zählen nur noch als Befehl, also nach `;`, `|`, `&&`, `` ` ``, `$(` oder einem Zeilenumbruch bzw. mit typischen Angaben wie `bash -c` oder `curl http://`. Suchbegriffe wie „cat food“ oder „more information“ und Adressen wie `/web-sh-shop/` treffen nicht mehr, `;cat /etc/passwd` weiterhin.
  - IP-Adresse mit Port nur noch als Ziel in einer URL (`//1.2.3.4:8080`, „mittel“); `/config.php` und `/settings.php` nur noch als aufgerufene Datei, nicht in Parametern oder Teilen eines Pfads. `/admin.php` nur noch als aufgerufene Datei.
  - Beim Update werden nur Muster angepasst, die noch genau dem Standard entsprechen (Muster, Schweregrad, eingeschaltet). Von Ihnen geänderte oder abgeschaltete Muster bleiben unverändert.

## 3.0.1 (2026-10-17)

- Fix: Das IPS hat Besucher gesperrt, die den Einstieg der Website direkt aufrufen (`/index.php` ohne Parameter). Das Muster für Skript-Endungen (`\.php$`) schlug auf die eigene Datei an. Beim Skript, das die Anfrage ausführt, prüft das IPS jetzt nur die Parameter; Angriffe dort werden weiterhin erkannt.

## 3.0.0 (2026-10-17)

- Formularschutz: Bei „Ausgenommene Formulare“ wird erklärt, was der Formularname ist, wie man ihn vergibt und wie man ein Formular direkt ausnimmt; bisher erkannte Formularnamen werden angezeigt. Warnung, wenn der Standardname „formular“ eingetragen wird.

## 3.0.0-beta1 (2026-10-17)

Komplett überarbeitet: Sicherheit nach aktuellem Stand, neue Oberfläche, Formularschutz für YForm, Speicherübersicht. Das Update von 2.x übernimmt Einstellungen, Rechte und Daten automatisch.

### Sicherheit

- Sperrbildschirm: Das alte Rechen-Captcha ließ sich fälschen; jede IP konnte entsperrt und auf die Positivliste gesetzt werden. Ersetzt durch ALTCHA (Proof-of-Work, ohne Cookies, ohne Fremddienst). Entsperrt wird nur die eigene IP, begrenzt und gegen Wiederverwendung geschützt.
- IP-Erkennung: Proxy-Header (X-Forwarded-For, CF-Connecting-IP usw.) wurden ungeprüft übernommen. Damit ließen sich Sperren umgehen und fremde IPs sperren. Jetzt gilt `REMOTE_ADDR`; Proxy-Header nur von eingetragenen vertrauenswürdigen Proxys.
- CSRF-Schutz und POST für alle Aktionen im Backend; reflektiertes XSS auf der Seite der gesperrten IPs behoben; Ausgaben durchgehend escaped.
- IPS: Die Ausnahme für „legitime“ Adressen ließ sich mit `?a=1` umgehen – jetzt werden Muster zuerst geprüft. Eigene Muster werden beim Speichern geprüft (auch gegen ReDoS). Fehler führen nicht mehr zu einer Fehlerseite für alle Besucher.
- Wartung: Passwort nur noch als Hash, nur per POST, begrenzte Fehlversuche; der Umgehungs-Link braucht einen geheimen Wert (`?access=1` reichte bisher). Freischaltungen enden, wenn Passwort oder Link geändert werden.
- System-Health-API: lieferte Daten auch nach „ungültiger Schlüssel“ und ohne gesetzten Schlüssel. Jetzt immer Schlüssel, nur 403 ohne Inhalt, keine Datenbank-Zugangsdaten mehr in der Ausgabe.
- Wartungs-API und E-Mail-Schutz-API: Token im Header, Vergleich mit konstanter Laufzeit, Begrenzung von Fehlversuchen, Schalt-Aktionen nur per POST.
- Keine Session mehr für jeden Besucher im Frontend; keine eigenen Einträge je IP in `rex_config`; keine Downloads oder externen Abrufe beim Seitenaufruf.

### Neu

- Eine Übersicht für alle, je nach Rolle mit passenden Kacheln; Wartung direkt dort schalten.
- Einstellungen an einer Stelle, aufgebaut wie die macOS-Systemeinstellungen; je Funktion ein Schalter, der sie wirklich ein- und ausschaltet. Bisher nur per Code einstellbare Werte (Anfragen begrenzen, Aufbewahrung, Bereinigung) haben jetzt Felder.
- Formularschutz für YForm: hängt sich automatisch ein, ohne Feld und ohne Captcha. Prüft Falle, Zeitstempel, unsichtbare Rechenaufgabe, Verhalten, KI-Agenten (Web Bot Auth, bekannte Kennungen), Inhalt und Häufigkeit. Seite mit abgewiesenen Einsendungen.
- Speicherübersicht wie in macOS (Medien nach Art, Datenbank, Cache, Backups, Logs, System), auch für Redakteure.
- Empfehlungen statt Security Advisor: ruhige Liste, prüft nur auf Knopfdruck, per Cronjob oder Konsole; Ausblenden für eine einstellbare Zeit; Bericht als JSON.
- Cronjob-Typen für Empfehlungen und Speicher; Konsolenbefehl `upkeep:storage`.
- Ansprechpartner für Redakteure in der Übersicht.
- Dunkles Theme; alle Texte auf Deutsch und Englisch (viele Platzhaltertexte aus 2.x ersetzt).

### Geändert

- Neue Navigation: Übersicht, Wartung, Schutz, Empfehlungen, Speicher, Einstellungen. Alle Rechte sind angemeldet und Rollen zuweisbar; alte Rechte werden beim Update übertragen.
- E-Mail-Schutz prüft nur noch Inhalte aus Besucher-Eingaben, bricht die Seite nicht mehr ab und meldet Inhalts-Treffer nicht mehr an das IPS (keine Sperren echter Besucher durch eigene Vorlagen).
- IPS-Ereignisse werden zusammengefasst und begrenzt; Bereinigung höchstens stündlich statt zufällig bei Anfragen.
- Berichte: Ereignisse für Wartung und Empfehlungen werden jetzt wirklich ausgelöst; Fehler aus dem System-Log kommen in den Sammelbericht.
- Menü zeigt nur noch an, wenn Wartung aktiv ist.

### Entfernt

- Getrennte Menü-Schalter `*_enabled`, versteckte Admin-Einstellungsseite, zweites Admin-Dashboard, veraltete Dateien (`api/security_advisor.php`, `api/system_health.php`, Testdateien, leere oder fehlerhafte CSS/JS-Dateien).

## 2.2.7 (2026-06-04)

- Fix: Admin-Dashboard zeigt keine ins Leere laufenden Links mehr, wenn Security Advisor oder IPS deaktiviert sind (Issue #59).
- Fix: Mail-Security-Filter greift nur noch im Frontend und blockiert keine Backend-Aktionen mehr (Issue #63).

## 2.2.6

- Siehe Git-Historie und bestehende Release-Notizen.
