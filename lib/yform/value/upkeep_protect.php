<?php

/**
 * upkeep: invisible spam protection element.
 *
 * Added automatically to frontend YForm forms by KLXM\Upkeep\FormProtection (EP YFORM_GENERATE).
 * It is not meant to be placed in a form definition (hidden in manager and formbuilder).
 * Opt-out per form: objparams|upkeep_spam_protection|0
 */
class rex_yform_value_upkeep_protect extends rex_yform_value_abstract
{
    public function preValidateAction(): void
    {
        \KLXM\Upkeep\FormProtection::process($this);
    }

    public function postValidateAction(): void
    {
        \KLXM\Upkeep\FormProtection::countSubmission($this);
    }

    public function enterObject()
    {
        // output is rendered in preValidateAction (like rex_yform_value_csrf)
    }

    public function getDescription(): string
    {
        return 'upkeep_protect|name';
    }

    public function getDefinitions(): array
    {
        return [
            'type' => 'value',
            'name' => 'upkeep_protect',
            'values' => [
                'name' => ['type' => 'name', 'label' => 'Name'],
            ],
            'description' => 'upkeep spam protection (added automatically)',
            'db_type' => ['none'],
            'multi_edit' => 'always',
            'is_searchable' => false,
            'is_hiddeninlist' => true,
            'hidden' => true,
            'formbuilder' => false,
            'manager' => false,
        ];
    }
}
