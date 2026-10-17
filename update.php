<?php

/**
 * Update: install.php legt Tabellen und Standarddaten idempotent an und führt die Migration aus 2.x aus.
 */

require __DIR__ . '/install.php';

// Ältere Muster aus 2.2.x verfeinern (unverändert übernommen)
require __DIR__ . '/install/legacy_patterns.php';

// Klassen-Cache leeren, damit neue Klassen auch für Frontend-Anfragen sofort gefunden werden
rex_delete_cache();
