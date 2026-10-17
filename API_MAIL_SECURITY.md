# E-Mail-Schutz-API

Mit der Schnittstelle verwalten Sie Badwords und Blocklist des E-Mail-Schutzes und lesen Status, Statistik und Ereignisse. Alle Antworten sind JSON.

## Aufruf und Anmeldung

```text
https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=<endpoint>
```

Die API nutzt das **Token der Wartungs-API** (Upkeep > Einstellungen > Schnittstellen). Es wird ausschließlich im Header übergeben:

```http
Authorization: Bearer <token>
```

Das Token muss mindestens 16 Zeichen lang sein. Es wird mit konstanter Laufzeit verglichen. Nach 10 fehlgeschlagenen Anmeldungen je IP innerhalb von 10 Minuten antwortet die API mit HTTP 429.

Hinweis: Die Schnittstelle bleibt auch erreichbar, wenn die Website im Wartungsmodus ist.

## Endpunkte

Der Parameter `endpoint` und die HTTP-Methode bestimmen die Aktion. Änderungen am Datenbestand erwarten einen JSON-Body (Größe bis 64 KB).

| Methode | `endpoint` | Parameter | Zweck |
|---|---|---|---|
| GET | `status` | | Status und Kennzahlen der letzten 24 Stunden |
| GET | `stats` | | Kennzahlen plus häufigste Bedrohungen und Verlauf der letzten 7 Tage |
| GET | `badwords` | `limit`, `offset`, `status` | Badwords auflisten |
| POST | `badwords` | JSON-Body | Badword anlegen |
| PUT | `badwords` | `id`, JSON-Body | Badword ändern |
| DELETE | `badwords` | `id` | Badword löschen |
| GET | `blocklist` | `limit`, `offset`, `type`, `status` | Blocklist auflisten |
| POST | `blocklist` | JSON-Body | Eintrag anlegen |
| PUT | `blocklist` | `id`, JSON-Body | Eintrag ändern |
| DELETE | `blocklist` | `id` | Eintrag löschen |
| GET | `threats` | `limit`, `offset`, `severity`, `type`, `from_date`, `to_date` | Ereignisse auflisten |

Listen: `limit` 1 bis 500 (Standard 50), `offset` ab 0. `status` filtert mit `0` oder `1`. `from_date` und `to_date` im Format `YYYY-MM-DD`. `severity` ist `low`, `medium`, `high` oder `critical`.

### Antwortformat

Erfolg:

```json
{ "status": "success", "data": { } }
```

Listen enthalten zusätzlich `"meta": { "limit": 50, "offset": 0, "count": 12 }`. Schreibende Aktionen liefern `"message"`, beim Anlegen von Blocklist-Einträgen zusätzlich `"data": { "id": 7 }`. Anlegen antwortet mit HTTP 201.

Fehler:

```json
{ "status": "error", "message": "Unauthorized" }
```

| HTTP | Bedeutung |
|---|---|
| 400 | ungültige Daten, ungültige ID, ungültiger Endpunkt oder fehlende Pflichtangabe |
| 401 | Token fehlt oder ist falsch |
| 404 | Eintrag nicht gefunden, bei Badwords auch: nicht löschbar (mitgeliefert) |
| 405 | HTTP-Methode nicht unterstützt |
| 422 | ungültiger regulärer Ausdruck |
| 429 | zu viele fehlgeschlagene Anmeldungen |
| 500 | interner Fehler (Details im System-Log) |

### Status

```bash
curl -H "Authorization: Bearer <token>" \
  "https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=status"
```

```json
{
  "status": "success",
  "data": {
    "active": true,
    "threats_24h": 45,
    "blocked_emails_24h": 12,
    "badwords_count": 156,
    "blocklist_count": 89,
    "rate_limit_blocks_24h": 3
  }
}
```

### Badwords

Felder der Antwort: `id`, `pattern`, `description`, `category`, `severity`, `is_regex`, `status`, `is_default`, `is_editable`, `created_at`, `updated_at`.

Anlegen (`pattern` ist Pflicht, `word` wird als Alias akzeptiert; Standard für `severity` ist `medium`, für `category` `general`):

```bash
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"pattern":"/\\bcasino\\b/i","is_regex":true,"severity":"high","category":"spam","description":"Glücksspiel"}' \
  "https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords"
```

Ändern: `PUT` mit `id` in der URL; nicht übergebene Felder bleiben unverändert (`pattern`, `description`, `category`, `severity`, `is_regex`, `status`). Reguläre Ausdrücke werden geprüft; ein ungültiger Ausdruck führt zu HTTP 422.

```bash
curl -X PUT -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"status":false}' \
  "https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&id=12"
```

### Blocklist

Anlegen mit `type` (`email`, `domain`, `ip`, `pattern`; Standard `email`) und `entry`. Optional: `severity` (Standard `medium`), `reason`, `status` und `expires_at` (Datum/Uhrzeit oder `null`). E-Mail-Adressen und IPs werden auf Gültigkeit geprüft.

```bash
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"type":"domain","entry":"spam-domain.example","severity":"high","reason":"Spam-Welle"}' \
  "https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist"
```

Ändern und Löschen funktionieren über `id` wie bei den Badwords. Nur Einträge mit Schwere `high` oder `critical` blockieren E-Mails.

### Ereignisse

Gelistet werden Ereignisse mit Typ `mail_*`. Felder: `id`, `ip_address`, `request_uri`, `threat_type`, `threat_category`, `pattern_matched`, `severity`, `action_taken`, `created_at`.

```bash
curl -H "Authorization: Bearer <token>" \
  "https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=threats&severity=high&from_date=2026-10-01&limit=20"
```

## PHP-Beispiel

```php
$ch = curl_init('https://example.org/index.php?rex-api-call=upkeep_mail_security&endpoint=status');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
    CURLOPT_TIMEOUT => 10,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$result = json_decode((string) $body, true);
```

Bewahren Sie das Token nicht im Code oder im Repository auf, und erneuern Sie es unter Einstellungen > Schnittstellen, wenn es bekannt geworden sein könnte.
