<?php
/**
 * Frontend-Wartungsseite
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();
$title = $addon->getConfig('maintenance_page_title', 'Site Maintenance');
$message = $addon->getConfig('maintenance_page_message', 'We are currently performing maintenance. Please check back soon.');
$showPasswordForm = $addon->getConfig('frontend_password', '') !== '';

// Prüfen, ob eine Passwort-Fehler angezeigt werden soll
$passwordError = false;
if (rex_request('upkeep_password', 'string', '') !== '' && !rex_session('upkeep_authorized', 'bool', false)) {
    $passwordError = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?= htmlspecialchars($title) ?></title>
    <meta name="robots" content="noindex,nofollow">
    <style>
        :root {
            --primary-color: #5b98d7;
            --text-color: #555;
            --bg-color: #f8f8f8;
            --card-bg: #ffffff;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
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
        }
        
        .maintenance-title {
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        
        .maintenance-message {
            font-size: 1.1rem;
            margin-bottom: 2rem;
        }
        
        .maintenance-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            fill: var(--primary-color);
            display: block;
        }
        
        .maintenance-password-form {
            margin-top: 2rem;
            max-width: 300px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .maintenance-input {
            display: block;
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 1rem;
            font-size: 1rem;
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
            transition: background-color 0.2s;
        }
        
        .maintenance-button:hover {
            background-color: #4a87c6;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
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
        }
        
        .error-message {
            color: #e74c3c;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="maintenance-container">
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
            <?php if ($passwordError): ?>
            <div class="error-message"><?= $addon->i18n('upkeep_wrong_password') ?></div>
            <?php endif; ?>
            
            <input type="password" name="upkeep_password" class="maintenance-input" placeholder="<?= $addon->i18n('upkeep_enter_password') ?>" required>
            <button type="submit" class="maintenance-button"><?= $addon->i18n('upkeep_submit') ?></button>
        </form>
        <?php endif; ?>
    </div>
</body>
</html>
