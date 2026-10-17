# Changelog

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
