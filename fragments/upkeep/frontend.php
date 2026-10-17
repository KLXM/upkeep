<?php
/**
 * Frontend-Wartungsseite mit Mehrsprachigkeitsunterstützung
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

// Mehrsprachigkeitslogik
$multilanguageEnabled = (bool) $addon->getConfig('multilanguage_enabled', 0);
$languageTexts = json_decode((string) $addon->getConfig('multilanguage_texts', '[]'), true);
$languageTexts = is_array($languageTexts) ? array_values(array_filter($languageTexts, static fn ($l) => is_array($l) && isset($l['language_code']) && is_string($l['language_code']) && preg_match('/^[a-zA-Z]{2,3}([_-][a-zA-Z0-9]{2,8})?$/', $l['language_code']))) : [];

// Aktuelle Sprache ermitteln - erste Sprache als Standard
$currentLanguage = !empty($languageTexts) ? (string) $languageTexts[0]['language_code'] : 'de';
$languagesByCode = [];

if ($multilanguageEnabled && !empty($languageTexts)) {
    foreach ($languageTexts as $lang) {
        $languagesByCode[$lang['language_code']] = $lang;
    }

    // Sprache aus URL-Parameter oder Cookie, Fallback auf erste verfügbare Sprache
    $requestedLang = rex_request('lang', 'string', '');
    if ($requestedLang !== '' && isset($languagesByCode[$requestedLang])) {
        $currentLanguage = $requestedLang;
        if (!headers_sent()) {
            setcookie('upkeep_lang', $currentLanguage, [
                'expires' => time() + (86400 * 30),
                'path' => '/',
                'samesite' => 'Lax',
                'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'httponly' => true,
            ]);
        }
    } elseif (is_string($cookieLang = $_COOKIE['upkeep_lang'] ?? '') && isset($languagesByCode[$cookieLang])) {
        $currentLanguage = $cookieLang;
    }
    if (!isset($languagesByCode[$currentLanguage])) {
        $currentLanguage = (string) array_key_first($languagesByCode);
    }
}

// Texte für die aktuelle Sprache ermitteln
$currentTexts = [];
if ($multilanguageEnabled && !empty($languageTexts)) {
    $currentTexts = $languagesByCode[$currentLanguage] ?? $languageTexts[0];
}

// Fallback auf alte Einstellungen wenn keine Mehrsprachigkeit oder keine Texte vorhanden
$title = (string) ($currentTexts['title'] ?? $addon->getConfig('maintenance_page_title', 'Wartungsarbeiten'));
$message = (string) ($currentTexts['message'] ?? $addon->getConfig('maintenance_page_message', 'Diese Website befindet sich derzeit im Wartungsmodus. Bitte versuchen Sie es später erneut.'));
$passwordLabel = (string) ($currentTexts['password_label'] ?? 'Passwort eingeben');
$passwordButton = (string) ($currentTexts['password_button'] ?? 'Anmelden');
$languageSwitchLabel = (string) ($currentTexts['language_switch'] ?? 'Sprache wählen');

$showPasswordForm = Upkeep::hasFrontendPassword();

// Fehlerzustand des Passwortformulars (nur nach einem POST)
$passwordErrorState = Upkeep::getPasswordError();
$passwordErrorText = '';
if ($passwordErrorState === 'locked') {
    $passwordErrorText = (string) ($currentTexts['password_locked'] ?? $addon->i18n('upkeep_frontend_password_locked'));
} elseif ($passwordErrorState === 'invalid') {
    $passwordErrorText = (string) ($currentTexts['password_error'] ?? $addon->i18n('upkeep_frontend_password_error'));
}
?>
<!DOCTYPE html>
<html lang="<?= rex_escape($currentLanguage) ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?= htmlspecialchars($title) ?></title>
    <style>
        :root {
            --primary-color: #5b98d7;
            --text-color: #555;
            --bg-color: #f8f8f8;
            --card-bg: #ffffff;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --error-color: #e74c3c;
            --border-color: #ddd;
            --button-hover: #4a87c6;
        }
        
        @media (prefers-color-scheme: dark) {
            :root {
                --primary-color: #64a0e0;
                --text-color: #e0e0e0;
                --bg-color: #121212;
                --card-bg: #1e1e1e;
                --shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
                --error-color: #e74c3c;
                --border-color: #444;
                --button-hover: #5590c9;
            }
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        
        .maintenance-container {
            max-width: 600px;
            padding: 2rem;
            background-color: var(--card-bg);
            border-radius: 8px;
            box-shadow: var(--shadow);
            text-align: center;
            animation: fadeIn 0.5s ease-in-out;
            position: relative;
        }
        
        .language-switcher {
            position: absolute;
            top: 1rem;
            right: 1rem;
            z-index: 100;
        }
        
        .language-dropdown {
            position: relative;
            display: inline-block;
        }
        
        .language-button {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            min-width: 160px;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        .language-button:hover {
            background: var(--button-hover);
            transform: translateY(-1px);
        }
        
        .language-button-text {
            display: inline-block;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .language-flag {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
            opacity: 0.8;
        }
        
        .language-code {
            display: inline-block;
            min-width: 28px;
            padding: 2px 6px;
            background: var(--bg-color);
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
            text-align: center;
            opacity: 0.7;
        }
        
        .language-option.active .language-code {
            background: rgba(255,255,255,0.2);
            opacity: 1;
        }
        
        .language-menu {
            position: absolute;
            top: 100%;
            right: 0;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            box-shadow: var(--shadow);
            min-width: 150px;
            opacity: 0;
            visibility: hidden;
            transform: translateY(-10px);
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .language-menu.active {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
        }
        
        .language-option {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.75rem 1rem;
            border: none;
            background: none;
            text-align: left;
            cursor: pointer;
            color: var(--text-color);
            transition: background-color 0.2s;
            font-size: 0.9rem;
        }
        
        .language-option:hover {
            background-color: var(--bg-color);
        }
        
        .language-option.active {
            background-color: var(--primary-color);
            color: white;
        }
        
        .maintenance-title {
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 1.5rem;
            font-weight: 700;
            opacity: 0;
            animation: slideInUp 0.6s ease 0.2s forwards;
        }
        
        .maintenance-message {
            font-size: 1.1rem;
            margin-bottom: 2rem;
            opacity: 0;
            animation: slideInUp 0.6s ease 0.4s forwards;
        }
        
        .maintenance-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            fill: var(--primary-color);
            display: block;
            opacity: 0;
            animation: slideInUp 0.6s ease 0.1s forwards;
        }
        
        .maintenance-password-form {
            margin-top: 2rem;
            max-width: 300px;
            margin-left: auto;
            margin-right: auto;
            opacity: 0;
            animation: slideInUp 0.6s ease 0.6s forwards;
        }
        
        .maintenance-input {
            display: block;
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            margin-bottom: 1rem;
            font-size: 1rem;
            background-color: var(--card-bg);
            color: var(--text-color);
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        
        .maintenance-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(91, 152, 215, 0.2);
        }
        
        .maintenance-button {
            display: inline-block;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .maintenance-button:hover {
            background-color: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        .error-message {
            color: var(--error-color);
            margin-bottom: 1rem;
            font-size: 0.9rem;
            padding: 0.5rem;
            background-color: rgba(231, 76, 60, 0.1);
            border-radius: 4px;
            border: 1px solid var(--error-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideInUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @media (max-width: 600px) {
            .maintenance-container {
                width: 90%;
                padding: 1.5rem;
            }
            
            .maintenance-title {
                font-size: 2rem;
            }
            
            .language-switcher {
                position: relative;
                top: auto;
                right: auto;
                margin-bottom: 1rem;
                text-align: center;
            }
            
            .language-button {
                min-width: 140px;
                font-size: 0.85rem;
            }
            
            .language-menu {
                right: auto;
                left: 50%;
                transform: translateX(-50%);
                min-width: 140px;
            }
        }
        
        /* Content fade transition for language switching */
        .content-fade {
            transition: opacity 0.3s ease;
        }
        
        .content-fade.fading {
            opacity: 0.3;
        }
    </style>
</head>
<body>
    <div class="maintenance-container">
        <?php if ($multilanguageEnabled && count($languageTexts) > 1): ?>
        <div class="language-switcher">
            <div class="language-dropdown">
                <button type="button" class="language-button" id="language-toggle" aria-label="<?= htmlspecialchars($languageSwitchLabel) ?>">
                    <svg class="language-flag" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M2 12h20"></path>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                    </svg>
                    <span class="language-button-text" id="language-text">Language Select</span>
                </button>
                <div class="language-menu" id="language-menu">
                    <?php 
                    foreach ($languageTexts as $lang): 
                        $isActive = $lang['language_code'] === $currentLanguage;
                    $langName = (string) ($lang['language_name'] ?? $lang['language_code']);
                    ?>
                    <button type="button" class="language-option <?= $isActive ? 'active' : '' ?>" 
                            data-lang="<?= htmlspecialchars($lang['language_code']) ?>">
                        <span class="language-code"><?= htmlspecialchars(strtoupper($lang['language_code'])) ?></span>
                        <?= htmlspecialchars($langName) ?>
                    </button>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <div class="content-fade" id="main-content">
            <svg class="maintenance-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            
            <h1 class="maintenance-title"><?= htmlspecialchars($title) ?></h1>
            <div class="maintenance-message">
                <?= nl2br(htmlspecialchars($message)) ?>
            </div>
            
            <?php if ($showPasswordForm): ?>
            <form class="maintenance-password-form" method="post">
                <?php if ($passwordErrorText !== ''): ?>
                <div class="error-message" role="alert"><?= rex_escape($passwordErrorText) ?></div>
                <?php endif; ?>
                
                <input type="password" name="upkeep_password" class="maintenance-input" 
                       placeholder="<?= htmlspecialchars($passwordLabel) ?>" aria-label="<?= htmlspecialchars($passwordLabel) ?>" autocomplete="current-password" maxlength="512" required>
                <button type="submit" class="maintenance-button"><?= htmlspecialchars($passwordButton) ?></button>
                
                <?php if ($multilanguageEnabled): ?>
                <input type="hidden" name="lang" value="<?= htmlspecialchars($currentLanguage) ?>">
                <?php endif; ?>
            </form>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($multilanguageEnabled && count($languageTexts) > 1): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const languageToggle = document.getElementById('language-toggle');
            const languageMenu = document.getElementById('language-menu');
            const languageOptions = document.querySelectorAll('.language-option');
            const mainContent = document.getElementById('main-content');
            const languageText = document.getElementById('language-text');
            
            // Apple-ähnliche Textrotation für den Button
            const languageLabels = [
                'Language Select',
                'Sprache wählen', 
                'Choisir la langue',
                'Seleziona lingua',
                'Seleccionar idioma',
                'Escolher idioma',
                'Välj språk',
                'Выберите язык',
                '言語を選択',
                '选择语言'
            ];
            
            let currentLabelIndex = 0;
            
            function rotateLanguageLabels() {
                if (!languageText) return;
                
                languageText.style.opacity = '0';
                languageText.style.transform = 'translateY(-10px)';
                
                setTimeout(() => {
                    currentLabelIndex = (currentLabelIndex + 1) % languageLabels.length;
                    languageText.textContent = languageLabels[currentLabelIndex];
                    languageText.style.opacity = '1';
                    languageText.style.transform = 'translateY(0)';
                }, 300);
            }
            
            // Animation alle 3 Sekunden
            if (languageText) {
                setInterval(rotateLanguageLabels, 3000);
            }
            
            // Toggle language dropdown
            languageToggle?.addEventListener('click', function(e) {
                e.stopPropagation();
                languageMenu.classList.toggle('active');
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', function() {
                languageMenu.classList.remove('active');
            });
            
            // Handle language selection
            languageOptions.forEach(option => {
                option.addEventListener('click', function(e) {
                    e.stopPropagation();
                    const selectedLang = this.dataset.lang;
                    
                    if (selectedLang !== <?= json_encode($currentLanguage, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>) {
                        // Add fading effect
                        mainContent.classList.add('fading');
                        
                        // Pause animation during transition
                        languageText.style.animation = 'none';
                        
                        setTimeout(() => {
                            // Redirect to the same page with new language parameter
                            const url = new URL(window.location);
                            url.searchParams.set('lang', selectedLang);
                            window.location.href = url.toString();
                        }, 300);
                    }
                    
                    languageMenu.classList.remove('active');
                });
            });
        });
    </script>
    <?php endif; ?>
</body>
</html>
