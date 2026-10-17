# E-Mail-Schutz

Der E-Mail-Schutz prüft E-Mails, die Besucher über Formulare der Website auslösen, bevor PHPMailer sie versendet. Er hilft gegen Spam, Header-Injection und den Missbrauch von Formularen als Spam-Schleuder.

Voraussetzung ist das AddOn PHPMailer. Der Schutz wird unter Upkeep > Einstellungen > Allgemein eingeschaltet und unter Einstellungen > E-Mail-Schutz konfiguriert. Listen und Ereignisse finden Sie unter Upkeep > Schutz > E-Mail (Reiter Ereignisse, Badwords, Blocklist, Muster). Das Recht dafür ist `upkeep[mail_security]`.

## Grundsätze

- **Nur Frontend.** Im Backend, in der Konsole und in Cronjobs greift der Schutz nie.
- **Nur Besucher-Eingaben.** Inhaltsprüfungen (Badwords, Spam-Muster, Code-Injection) laufen nur auf Texten, die aus POST- oder GET-Werten stammen und tatsächlich in der E-Mail vorkommen. Ihre eigenen E-Mail-Vorlagen werden nicht geprüft. Technische Felder (CSRF, Token, Captcha, Passwörter) bleiben außen vor.
- **Kein Abbruch der Seite.** Eine blockierte E-Mail wird nicht versendet: Die Empfänger werden entfernt, `send()` liefert `false`. Die Seite läuft normal weiter, es gibt kein `exit` mitten in einer YForm-Aktion.
- **Inhalte eskalieren nie.** Treffer im Inhalt führen nicht zu einer IP-Sperre durch das IPS. Gemeldet werden nur Versandgrenzen-Verstöße (Stufe „medium“).
- **Fehlertolerant.** Tritt im Filter ein Fehler auf, wird die E-Mail normal versendet und der Fehler im System-Log protokolliert.

## Was geprüft wird

| Prüfung | Verhalten |
|---|---|
| Versandgrenzen je IP | pro Minute, Stunde und Tag; bei Überschreitung wird blockiert |
| IP-Blocklist | Sperrliste des E-Mail-Schutzes und gesperrte IPs des IPS |
| Empfänger | An, Cc, Bcc und Reply-To gegen die Blocklist (E-Mail-Adresse, Domain) |
| Absender | Format der Absenderadresse, optional nur erlaubte Domains |
| Header-Injection | Zeilenumbrüche in Betreff oder Absendername |
| Code-Injection | Skript- und Code-Muster in den Besucher-Eingaben |
| Badwords | eigene Wörter und Regex-Muster in den Besucher-Eingaben |
| Spam-Muster | mitgelieferte Muster; bei Schwere „high“ wird ab dem dritten Treffer innerhalb von 24 Stunden blockiert |

Blockiert wird bei Schwere „high“ oder „critical“. Treffer niedrigerer Schwere werden nur protokolliert.

Eigene Absender-IPs (zum Beispiel Ihr Server oder ein Monitoring) tragen Sie unter Einstellungen > E-Mail-Schutz > Absender als vertrauenswürdig ein. Von dort versendete E-Mails werden nicht geprüft.

## Einstellungen

Unter Einstellungen > E-Mail-Schutz:

| Gruppe | Inhalt |
|---|---|
| Schalter | E-Mail-Schutz ein/aus |
| Prüfungen | Betreff, Inhalt, Absender; Inhalt bereinigen |
| Versandgrenzen | Grenzen je Minute, Stunde, Tag; Sperrdauer; Spam-Versuche bis zur Sperre |
| Absender | erlaubte Absender-Domains, vertrauenswürdige Absender-IPs |
| Benachrichtigung | Admin-Adresse und Mindest-Schwere |
| Protokoll | ausführliches Protokoll, Fehlersuche |

Eine Aktion in diesem Bereich bereinigt alte Protokolleinträge.

## Badwords und Muster

Ein Eintrag besteht aus Muster, Beschreibung, Kategorie und Schwere (`low`, `medium`, `high`, `critical`). Aktivieren Sie „Regex“, wird das Muster als regulärer Ausdruck mit Delimitern verwendet, zum Beispiel:

```text
/\b(casino|viagra)\b/i
```

Reguläre Ausdrücke werden beim Speichern geprüft: Syntaxfehler und Ausdrücke, die bei einer Testeingabe an Backtracking-Grenzen scheitern, werden abgelehnt. Das gilt auch für Einträge über die API. Mitgelieferte Muster (Reiter Muster) können Sie ein- und ausschalten oder anpassen; mitgelieferte Badwords lassen sich nicht löschen.

## Blocklist

Typen: `email` (genaue Adresse), `domain`, `ip` und `pattern`. Einträge haben eine Schwere, einen optionalen Grund und ein optionales Ablaufdatum. Nur Einträge mit Schwere „high“ oder „critical“ blockieren; andere werden protokolliert.

## Blockierte Mails in eigenem Code erkennen

```php
$mail = new rex_mailer();
$mail->addAddress('info@example.org');
$mail->Subject = 'Anfrage';
$mail->Body = $text;

if (!$mail->send()) {
    $reason = rex::getProperty('upkeep_mail_blocked'); // z. B. 'badword', 'rate_limit', 'header_injection'
    // Grund für Besucher neutral formulieren, nicht den Grund ausgeben
}
```

`upkeep_mail_blocked` ist nur gesetzt, wenn der E-Mail-Schutz den Versand verhindert hat. Mögliche Werte: `rate_limit`, `blocklisted_ip`, `blocklisted_recipient`, `invalid_sender_domain`, `header_injection`, `code_injection`, `badword`, `spam`.

## PHP-Klasse

`KLXM\Upkeep\MailSecurityFilter` (Auswahl):

```php
use KLXM\Upkeep\MailSecurityFilter;

MailSecurityFilter::addBadword('/\bcasino\b/i', 'high', 'spam', true, 'Beschreibung');
MailSecurityFilter::removeBadword($id);
MailSecurityFilter::addEmailBlocklist('spam@example.org', '', 'Grund', 'high', 'email');
MailSecurityFilter::getDashboardStats();
```

## Schnittstelle

Badwords, Blocklist und Ereignisse lassen sich per API verwalten, siehe [API_MAIL_SECURITY.md](API_MAIL_SECURITY.md).

## Tabellen

`rex_upkeep_mail_badwords`, `rex_upkeep_mail_blocklist`, `rex_upkeep_mail_default_patterns`, `rex_upkeep_mail_rate_limit` und `rex_upkeep_mail_threat_log`. Ereignisse mit dem Typ `mail_*` stehen zusätzlich in `rex_upkeep_ips_threat_log`.

## Fehlersuche

- **E-Mail wird fälschlich blockiert:** Unter Schutz > E-Mail > Ereignisse sehen Sie Typ und Muster des Treffers. Passen Sie das Muster an oder schalten Sie es aus; bei Versandgrenzen erhöhen Sie die Werte.
- **Nichts wird geprüft:** Der Schutz muss eingeschaltet sein, PHPMailer verfügbar, und der Versand muss im Frontend durch eine Besucher-Anfrage ausgelöst werden. Eine vertrauenswürdige Absender-IP umgeht die Prüfung.
- **Falsche IP im Protokoll:** Hinter Load-Balancer oder CDN tragen Sie dessen Adressen unter Einstellungen > Allgemein > Vertrauenswürdige Proxys ein.
- **Fehlersuche einschalten:** Einstellungen > E-Mail-Schutz > Protokoll > Fehlersuche; Ausgaben stehen im REDAXO-System-Log.
