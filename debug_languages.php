<?php
/**
 * Debug-Script für Mehrsprachigkeits-Texte
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

echo "<h1>Upkeep Mehrsprachigkeits-Debug</h1>";

echo "<h2>Konfiguration:</h2>";
echo "<strong>Mehrsprachigkeit aktiviert:</strong> " . ($addon->getConfig('multilanguage_enabled', 0) ? 'Ja' : 'Nein') . "<br>";
echo "<strong>Standard-Sprache:</strong> " . $addon->getConfig('multilanguage_default', 'nicht gesetzt') . "<br>";

echo "<h2>Rohe Sprachtexte (JSON):</h2>";
echo "<pre>" . htmlspecialchars($addon->getConfig('multilanguage_texts', 'nicht gesetzt')) . "</pre>";

echo "<h2>Dekodierte Sprachtexte:</h2>";
$languageTexts = json_decode($addon->getConfig('multilanguage_texts', '[]'), true);
if ($languageTexts) {
    foreach ($languageTexts as $index => $lang) {
        echo "<h3>Sprache #{$index}:</h3>";
        echo "<table border='1'>";
        foreach ($lang as $key => $value) {
            echo "<tr><td><strong>{$key}:</strong></td><td>" . htmlspecialchars($value) . "</td></tr>";
        }
        echo "</table><br>";
    }
} else {
    echo "Keine Sprachtexte gefunden oder JSON-Fehler.";
}

echo "<h2>JSON-Validierung:</h2>";
$jsonError = json_last_error();
if ($jsonError === JSON_ERROR_NONE) {
    echo "<span style='color: green;'>✅ JSON ist gültig</span>";
} else {
    echo "<span style='color: red;'>❌ JSON-Fehler: " . json_last_error_msg() . "</span>";
}

echo "<h2>URL-Parameter:</h2>";
echo "<strong>Angeforderte Sprache (lang):</strong> " . (rex_request('lang', 'string', '') ?: 'nicht gesetzt') . "<br>";

echo "<h2>Cookies:</h2>";
echo "<strong>Upkeep-Sprach-Cookie:</strong> " . ($_COOKIE['upkeep_lang'] ?? 'nicht gesetzt') . "<br>";

echo "<h2>Test-Links:</h2>";
if ($languageTexts) {
    foreach ($languageTexts as $lang) {
        if (isset($lang['language_code'])) {
            $code = $lang['language_code'];
            $name = $lang['language_name'] ?? $code;
            echo "<a href='?lang={$code}'>{$name} ({$code})</a> | ";
        }
    }
}
?>
