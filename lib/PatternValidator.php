<?php

namespace KLXM\Upkeep;

/**
 * Prüft und führt reguläre Ausdrücke aus Admin-Eingaben sicher aus.
 */
final class PatternValidator
{
    /**
     * Prüft, ob ein regulärer Ausdruck gültig ist (inkl. Delimiter).
     * Liefert false bei Syntaxfehlern oder wenn der Ausdruck bei einer
     * Testeingabe an Backtracking-/Rekursionsgrenzen scheitert (ReDoS-Verdacht).
     */
    public static function isValid(string $pattern): bool
    {
        return self::getError($pattern) === null;
    }

    /**
     * Liefert eine Fehlerbeschreibung oder null, wenn der Ausdruck gültig ist.
     */
    public static function getError(string $pattern): ?string
    {
        if (trim($pattern) === '') {
            return 'empty pattern';
        }
        if (strlen($pattern) > 2000) {
            return 'pattern too long';
        }

        $error = null;
        set_error_handler(static function (int $errno, string $errstr) use (&$error): bool {
            $error = $errstr;
            return true;
        });
        try {
            $result = preg_match($pattern, '');
        } finally {
            restore_error_handler();
        }
        if ($result === false || $error !== null) {
            return $error ?? preg_last_error_msg();
        }

        // Kurzer ReDoS-Test mit typischer Problemeingabe
        $oldLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '100000');
        try {
            $probe = str_repeat('a', 2000) . '!' . str_repeat('<a ', 200);
            set_error_handler(static fn (): bool => true);
            try {
                $res = preg_match($pattern, $probe);
            } finally {
                restore_error_handler();
            }
            if ($res === false) {
                return 'pattern too complex: ' . preg_last_error_msg();
            }
        } finally {
            if ($oldLimit !== false) {
                ini_set('pcre.backtrack_limit', $oldLimit);
            }
        }

        return null;
    }

    /**
     * Führt preg_match sicher aus: true = Treffer, false = kein Treffer,
     * null = Fehler (ungültiger Ausdruck oder Limit erreicht).
     */
    public static function match(string $pattern, string $subject): ?bool
    {
        set_error_handler(static fn (): bool => true);
        try {
            $res = preg_match($pattern, $subject);
        } finally {
            restore_error_handler();
        }
        if ($res === false) {
            return null;
        }
        return $res === 1;
    }
}
