<?php

namespace KLXM\Upkeep\Schema;

use rex;
use rex_sql_column;
use rex_sql_index;
use rex_sql_table;

/**
 * Tables of the YForm spam protection. Called from install.php / update.php (idempotent).
 */
final class FormProtectionSchema
{
    public static function ensure(): void
    {
        rex_sql_table::get(rex::getTable('upkeep_form_log'))
            ->ensurePrimaryIdColumn()
            ->ensureColumn(new rex_sql_column('form_name', 'varchar(191)', false, ''))
            ->ensureColumn(new rex_sql_column('reasons', 'varchar(255)', false, ''))
            ->ensureColumn(new rex_sql_column('score', 'int(11)', false, '0'))
            ->ensureColumn(new rex_sql_column('ip_address', 'varchar(45)', false, ''))
            ->ensureColumn(new rex_sql_column('user_agent', 'varchar(255)', false, ''))
            ->ensureColumn(new rex_sql_column('url', 'varchar(255)', false, ''))
            ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
            ->ensureIndex(new rex_sql_index('created_at', ['created_at']))
            ->ensureIndex(new rex_sql_index('ip_address', ['ip_address']))
            ->ensure();
    }

    public static function drop(): void
    {
        rex_sql_table::get(rex::getTable('upkeep_form_log'))->drop();
    }
}
