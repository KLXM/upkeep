<?php

/**
 * ALTCHA challenge endpoint (self-hosted, no third party).
 *
 * GET index.php?rex-api-call=upkeep_altcha[&scope=form|unlock]
 * Returns a signed proof-of-work challenge as JSON. No state change, therefore no CSRF token;
 * rate limited per client IP (see KLXM\Upkeep\Altcha::sendChallengeResponse()).
 */
class rex_api_upkeep_altcha extends rex_api_function
{
    protected $published = true;

    public function execute(): never
    {
        \KLXM\Upkeep\Altcha::sendChallengeResponse(rex_get('scope', 'string', 'form'));
    }

    protected function requiresCsrfProtection(): bool
    {
        return false;
    }
}
