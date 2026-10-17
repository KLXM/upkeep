<?php

/**
 * Speicher: Aufschlüsselung des Speicherverbrauchs der Website (wie in macOS).
 * Alle mit upkeep[] sehen die Übersicht, berechnen und Cache leeren nur Admins.
 */

use KLXM\Upkeep\Storage;

$addon = rex_addon::get('upkeep');
rex_view::addCssFile($addon->getAssetsUrl('css/storage.css'));

$csrf = rex_csrf_token::factory('upkeep_storage');
if ($result = Storage::handlePost($csrf)) {
    echo 'success' === $result['type'] ? rex_view::success($result['message']) : rex_view::error($result['message']);
}

$fragment = new rex_fragment();
$fragment->setVar('report', Storage::getReport(), false);
$fragment->setVar('canRefresh', rex::requireUser()->isAdmin(), false);
$fragment->setVar('csrf', $csrf, false);
$fragment->setVar('action', rex_url::currentBackendPage(), false);

$section = new rex_fragment();
$section->setVar('title', $addon->i18n('upkeep_storage_title'), false);
$section->setVar('body', $fragment->parse('upkeep/storage.php'), false);
echo $section->parse('core/page/section.php');
