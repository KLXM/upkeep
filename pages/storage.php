<?php

/**
 * Speicher: Aufschlüsselung des Speicherverbrauchs der Website (wie in macOS).
 * Alle mit upkeep[] sehen die Übersicht, berechnen und Cache leeren nur Admins.
 */

use KLXM\Upkeep\Storage;

$addon = rex_addon::get('upkeep');

$csrf = rex_csrf_token::factory('upkeep_storage');
if ($result = Storage::handlePost($csrf)) {
    echo 'success' === $result['type'] ? rex_view::success($result['message']) : rex_view::error($result['message']);
}

$fragment = new rex_fragment();
$fragment->setVar('report', Storage::getReport(), false);
$fragment->setVar('canRefresh', rex::requireUser()->isAdmin(), false);
$fragment->setVar('csrf', $csrf, false);
$fragment->setVar('action', rex_url::currentBackendPage(), false);

echo $fragment->parse('upkeep/storage.php');
