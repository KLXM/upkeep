# Mail Security API Documentation

## Übersicht

Die Mail Security API bietet RESTful Endpoints zur programmatischen Verwaltung des Mail Security Systems. Alle Endpoints erfordern eine Authentifizierung über API-Token.

## Authentifizierung

### API Token generieren

1. **Backend**: `Upkeep → Settings → API Token → Generate Token`
2. **Programmatisch**:
   ```php
   $addon = rex_addon::get('upkeep');
   $token = bin2hex(random_bytes(32));
   $addon->setConfig('api_token', $token);
   ```

### Token verwenden

**Header**:
```http
Authorization: Bearer YOUR_API_TOKEN_HERE
Content-Type: application/json
```

**Beispiel**:
```bash
curl -X GET \
  https://your-domain.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=status \
  -H 'Authorization: Bearer abc123def456...'
```

## Base URL

```
https://your-domain.com/redaxo/index.php?rex-api-call=upkeep_mail_security
```

## Endpoints

### 1. System Status

**GET** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=status`

Gibt den aktuellen Status des Mail Security Systems zurück.

**Response**:
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

**cURL Beispiel**:
```bash
curl -X GET \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=status" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Badwords Management

#### Badwords abrufen

**GET** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords`

**Parameter**:
- `limit` (int): Anzahl Einträge (Standard: 50)
- `offset` (int): Offset für Paginierung (Standard: 0)
- `status` (int): Filter nach Status (0=inaktiv, 1=aktiv)

**Beispiel**:
```bash
curl -X GET \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&limit=10&status=1" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response**:
```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "word": "casino",
            "is_regex": 0,
            "severity": "high",
            "category": "spam",
            "status": 1,
            "created_at": "2024-01-15 10:30:00",
            "updated_at": "2024-01-15 10:30:00"
        }
    ],
    "meta": {
        "limit": 10,
        "offset": 0,
        "count": 1
    }
}
```

#### Badword hinzufügen

**POST** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords`

**Body**:
```json
{
    "word": "spam",
    "severity": "high",
    "is_regex": false,
    "category": "spam",
    "status": 1
}
```

**Beispiel**:
```bash
curl -X POST \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "word": "casino",
    "severity": "high",
    "category": "spam"
  }'
```

**Response**:
```json
{
    "status": "success",
    "message": "Badword added successfully",
    "data": {
        "id": 123
    }
}
```

#### Badword aktualisieren

**PUT** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&id=123`

**Body**:
```json
{
    "word": "updated-word",
    "severity": "medium",
    "status": 0
}
```

**Beispiel**:
```bash
curl -X PUT \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&id=123" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "low",
    "status": 0
  }'
```

#### Badword löschen

**DELETE** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&id=123`

**Beispiel**:
```bash
curl -X DELETE \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=badwords&id=123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Blocklist Management

#### Blocklist abrufen

**GET** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist`

**Parameter**:
- `limit` (int): Anzahl Einträge
- `offset` (int): Offset für Paginierung
- `type` (string): Filter nach Typ (ip, domain, email)
- `status` (int): Filter nach Status

**Beispiel**:
```bash
curl -X GET \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist&type=ip&status=1" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response**:
```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "entry": "192.168.1.100",
            "type": "ip",
            "ip_address": "192.168.1.100",
            "reason": "Spam source",
            "status": 1,
            "expires_at": null,
            "created_at": "2024-01-15 10:30:00",
            "updated_at": "2024-01-15 10:30:00"
        }
    ],
    "meta": {
        "limit": 50,
        "offset": 0,
        "count": 1
    }
}
```

#### Zur Blocklist hinzufügen

**POST** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist`

**Body**:
```json
{
    "entry": "spam-domain.com",
    "type": "domain",
    "reason": "Known spam domain",
    "expires_at": "2024-12-31 23:59:59"
}
```

**Beispiel**:
```bash
curl -X POST \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "entry": "evil-spammer.com",
    "type": "domain",
    "reason": "Confirmed spam domain"
  }'
```

#### Blocklist-Eintrag aktualisieren

**PUT** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist&id=123`

**Body**:
```json
{
    "reason": "Updated reason",
    "status": 0,
    "expires_at": "2024-06-30 23:59:59"
}
```

#### Blocklist-Eintrag löschen

**DELETE** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=blocklist&id=123`

### 4. Threat Log

#### Bedrohungen abrufen

**GET** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=threats`

**Parameter**:
- `limit` (int): Anzahl Einträge (Standard: 50)
- `offset` (int): Offset für Paginierung
- `severity` (string): Filter nach Schweregrad (low, medium, high, critical)
- `type` (string): Filter nach Bedrohungstyp
- `from_date` (string): Startdatum (YYYY-MM-DD)
- `to_date` (string): Enddatum (YYYY-MM-DD)

**Beispiel**:
```bash
curl -X GET \
  "https://example.com/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=threats&severity=high&from_date=2024-01-01&limit=100" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response**:
```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "threat_type": "mail_badword",
            "severity": "high",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "email_data": {
                "subject": "Win big at our casino!",
                "from": "spammer@evil.com",
                "to": "user@example.com"
            },
            "threat_details": {
                "badword": "casino",
                "pattern_id": 15
            },
            "blocked": 1,
            "created_at": "2024-01-15 14:30:22"
        }
    ],
    "meta": {
        "limit": 100,
        "offset": 0,
        "count": 1
    }
}
```

### 5. Erweiterte Statistiken

#### Detaillierte Statistiken abrufen

**GET** `/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=stats`

**Response**:
```json
{
    "status": "success",
    "data": {
        "active": true,
        "threats_24h": 45,
        "blocked_emails_24h": 12,
        "badwords_count": 156,
        "blocklist_count": 89,
        "rate_limit_blocks_24h": 3,
        "top_threats": [
            {
                "threat_type": "mail_badword",
                "count": 25
            },
            {
                "threat_type": "mail_blocklist_domain",
                "count": 15
            }
        ],
        "threats_per_day": [
            {
                "date": "2024-01-15",
                "count": 45
            },
            {
                "date": "2024-01-14",
                "count": 32
            }
        ]
    }
}
```

## Fehlerbehandlung

### HTTP Status Codes

| Code | Beschreibung |
|------|--------------|
| 200 | Erfolg |
| 201 | Erstellt |
| 400 | Ungültige Anfrage |
| 401 | Nicht autorisiert |
| 404 | Nicht gefunden |
| 405 | Methode nicht erlaubt |
| 500 | Serverfehler |

### Fehler-Response Format

```json
{
    "status": "error",
    "message": "Detailed error message"
}
```

### Häufige Fehler

#### 401 Unauthorized

```json
{
    "status": "error",
    "message": "Unauthorized"
}
```

**Ursachen**:
- Fehlender oder ungültiger API-Token
- API nicht aktiviert

#### 400 Bad Request

```json
{
    "status": "error",
    "message": "Word is required"
}
```

**Ursachen**:
- Pflichtfelder fehlen
- Ungültiges JSON-Format
- Ungültige Parameter

## PHP SDK Beispiele

### Einfacher API Client

```php
<?php
class UpkeepMailSecurityAPI
{
    private $baseUrl;
    private $token;

    public function __construct(string $baseUrl, string $token)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token = $token;
    }

    private function request(string $method, string $endpoint, array $data = null): array
    {
        $url = $this->baseUrl . '/redaxo/index.php?rex-api-call=upkeep_mail_security&endpoint=' . $endpoint;
        
        $options = [
            'http' => [
                'method' => strtoupper($method),
                'header' => [
                    'Authorization: Bearer ' . $this->token,
                    'Content-Type: application/json'
                ]
            ]
        ];

        if ($data && in_array(strtoupper($method), ['POST', 'PUT'])) {
            $options['http']['content'] = json_encode($data);
        }

        $context = stream_context_create($options);
        $response = file_get_contents($url, false, $context);
        
        return json_decode($response, true);
    }

    public function getStatus(): array
    {
        return $this->request('GET', 'status');
    }

    public function getBadwords(int $limit = 50, int $offset = 0): array
    {
        return $this->request('GET', "badwords&limit={$limit}&offset={$offset}");
    }

    public function addBadword(string $word, string $severity = 'medium', bool $isRegex = false): array
    {
        return $this->request('POST', 'badwords', [
            'word' => $word,
            'severity' => $severity,
            'is_regex' => $isRegex
        ]);
    }

    public function addToBlocklist(string $entry, string $type, string $reason = ''): array
    {
        return $this->request('POST', 'blocklist', [
            'entry' => $entry,
            'type' => $type,
            'reason' => $reason
        ]);
    }

    public function getThreats(array $filters = []): array
    {
        $params = http_build_query($filters);
        return $this->request('GET', 'threats' . ($params ? '&' . $params : ''));
    }
}

// Verwendung
$api = new UpkeepMailSecurityAPI('https://your-domain.com', 'your-api-token');

// Status abrufen
$status = $api->getStatus();
echo "Mail Security ist " . ($status['data']['active'] ? 'aktiv' : 'inaktiv') . "\n";

// Badword hinzufügen
$result = $api->addBadword('casino', 'high');
if ($result['status'] === 'success') {
    echo "Badword erfolgreich hinzugefügt!\n";
}

// Domain sperren
$result = $api->addToBlocklist('spam-domain.com', 'domain', 'Bekannte Spam-Domain');

// Bedrohungen der letzten 24h
$threats = $api->getThreats(['from_date' => date('Y-m-d', strtotime('-1 day'))]);
echo "Bedrohungen: " . count($threats['data']) . "\n";
```

### Async Client mit Guzzle

```php
<?php
use GuzzleHttp\Client;
use GuzzleHttp\Promise;

class UpkeepMailSecurityAsyncAPI
{
    private $client;
    private $baseUrl;
    private $headers;

    public function __construct(string $baseUrl, string $token)
    {
        $this->baseUrl = rtrim($baseUrl, '/') . '/redaxo/index.php';
        $this->client = new Client();
        $this->headers = [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ];
    }

    public function batchOperations(): Promise\PromiseInterface
    {
        $promises = [
            'status' => $this->client->getAsync($this->baseUrl, [
                'query' => ['rex-api-call' => 'upkeep_mail_security', 'endpoint' => 'status'],
                'headers' => $this->headers
            ]),
            'badwords' => $this->client->getAsync($this->baseUrl, [
                'query' => ['rex-api-call' => 'upkeep_mail_security', 'endpoint' => 'badwords'],
                'headers' => $this->headers
            ]),
            'threats' => $this->client->getAsync($this->baseUrl, [
                'query' => [
                    'rex-api-call' => 'upkeep_mail_security',
                    'endpoint' => 'threats',
                    'limit' => 10
                ],
                'headers' => $this->headers
            ])
        ];

        return Promise\settle($promises);
    }
}

// Verwendung
$asyncAPI = new UpkeepMailSecurityAsyncAPI('https://your-domain.com', 'your-token');

$asyncAPI->batchOperations()->then(function ($results) {
    foreach ($results as $key => $result) {
        if ($result['state'] === 'fulfilled') {
            $data = json_decode($result['value']->getBody(), true);
            echo "✅ {$key}: " . $data['status'] . "\n";
        } else {
            echo "❌ {$key}: Fehler\n";
        }
    }
});
```

## Webhook Integration

### Webhook-Endpoint einrichten

```php
<?php
// webhook.php
$payload = json_decode(file_get_contents('php://input'), true);
$signature = $_SERVER['HTTP_X_UPKEEP_SIGNATURE'] ?? '';

// Signatur verifizieren
$secret = 'your-webhook-secret';
$expectedSignature = hash_hmac('sha256', file_get_contents('php://input'), $secret);

if (!hash_equals($expectedSignature, $signature)) {
    http_response_code(401);
    exit('Unauthorized');
}

// Event verarbeiten
switch ($payload['event']) {
    case 'mail_threat_detected':
        // Bedrohung erkannt
        $threat = $payload['data'];
        logThreat($threat);
        break;
        
    case 'mail_blocked':
        // E-Mail blockiert
        $email = $payload['data'];
        notifyAdmin($email);
        break;
        
    case 'badword_added':
        // Neues Badword hinzugefügt
        $badword = $payload['data'];
        updateLocalCache($badword);
        break;
}

http_response_code(200);
echo 'OK';
```

## Rate Limiting

Die API implementiert Rate Limiting um Missbrauch zu verhindern:

- **Standard**: 1000 Requests pro Stunde pro API-Token
- **Burst**: 100 Requests pro Minute
- **Headers**: Rate Limit Informationen in Response Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Monitoring & Logging

### API Calls verfolgen

```php
// API-Zugriffe protokollieren
rex_extension::register('UPKEEP_API_CALL', function($ep) {
    $endpoint = $ep->getParam('endpoint');
    $method = $ep->getParam('method');
    $ip = $ep->getParam('ip');
    
    rex_logger::factory()->info('API Call', [
        'endpoint' => $endpoint,
        'method' => $method,
        'ip' => $ip,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
});
```

### Performance Monitoring

```php
// API Performance messen
$start = microtime(true);
$result = $api->getThreats();
$duration = microtime(true) - $start;

if ($duration > 2.0) {
    // Warnung bei langsamen API-Calls
    error_log("Slow API call: threats endpoint took {$duration}s");
}
```

---

*Diese API-Dokumentation wird kontinuierlich erweitert und aktualisiert.*