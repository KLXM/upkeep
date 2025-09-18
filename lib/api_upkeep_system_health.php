<?php
/**
 * Upkeep AddOn - System Health API Handler
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

class rex_api_upkeep_system_health extends rex_api_function
{
    protected $published = true;

    public function execute()
    {
        $addon = rex_addon::get('upkeep');
        
        // Check if System Health API is enabled
        if (!$addon->getConfig('system_health_enabled', false)) {
            return new rex_api_result(false, [
                'error' => 'System Health API is disabled',
                'status' => 'disabled'
            ]);
        }
        
        // Validate health key
        $configuredKey = $addon->getConfig('system_health_key', '');
        $providedKey = rex_request('health_key', 'string');

        if (empty($configuredKey) || $configuredKey !== $providedKey) {
            return new rex_api_result(false, [
                'error' => 'Unauthorized',
                'message' => 'Invalid or missing health key'
            ]);
        }

        // Include the system health logic
        ob_start();
        include rex_addon::get('upkeep')->getPath('api/system_health.php');
        $output = ob_get_clean();
        
        // Since the system_health.php handles its own output, we'll exit here
        echo $output;
        exit;
    }
}