    /**
     * Aktualisiert ein Custom Pattern
     */
    public static function updateCustomPattern(int $id, string $pattern, string $description = '', string $severity = 'medium', bool $isRegex = false, bool $status = true): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setWhere(['id' => $id]);
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', $severity);
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', $status ? 1 : 0);
            $sql->setRawValue('updated_at', 'NOW()');
            $sql->update();
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Entfernt ein Custom Pattern
     */
    public static function removeCustomPattern(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setWhere(['id' => $id]);
            $sql->delete();
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Schaltet den Status eines Custom Patterns um
     */
    public static function toggleCustomPatternStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("UPDATE " . rex::getTable('upkeep_ips_custom_patterns') . " 
                           SET status = 1 - status, updated_at = NOW() 
                           WHERE id = ?", [$id]);
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Lädt ein Custom Pattern für die Bearbeitung
     */
    public static function getCustomPattern(int $id): ?array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_custom_patterns') . " WHERE id = ?", [$id]);
            if ($sql->getRows() > 0) {
                return [
                    'id' => $sql->getValue('id'),
                    'pattern' => $sql->getValue('pattern'),
                    'description' => $sql->getValue('description'),
                    'severity' => $sql->getValue('severity'),
                    'is_regex' => (bool) $sql->getValue('is_regex'),
                    'status' => (bool) $sql->getValue('status'),
                    'created_at' => $sql->getValue('created_at'),
                    'updated_at' => $sql->getValue('updated_at')
                ];
            }
            return null;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return null;
        }
    }
