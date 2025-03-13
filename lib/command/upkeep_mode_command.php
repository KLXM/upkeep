<?php

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use KLXM\Upkeep\Upkeep;

/**
 * Konsolen-Kommando zum Aktivieren/Deaktivieren des Wartungsmodus
 */
class rex_upkeep_mode_command extends rex_console_command
{
    protected function configure(): void
    {
        $this
            ->setName('upkeep:mode')
            ->setDescription('Aktiviert oder deaktiviert den Wartungsmodus')
            ->addArgument(
                'target',
                InputArgument::REQUIRED,
                'Ziel: "frontend" oder "backend"'
            )
            ->addArgument(
                'state',
                InputArgument::REQUIRED,
                'Status: "on" oder "off"'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getStyle($input, $output);
        $io->title('Upkeep - Wartungsmodus');

        $target = $input->getArgument('target');
        $state = $input->getArgument('state');
        
        // Zielüberprüfung
        if (!in_array($target, ['frontend', 'backend'], true)) {
            $io->error('Ungültiges Ziel. Erlaubt sind "frontend" oder "backend".');
            return Command::INVALID;
        }
        
        // Statusüberprüfung
        if (!in_array($state, ['on', 'off'], true)) {
            $io->error('Ungültiger Status. Erlaubt sind "on" oder "off".');
            return Command::INVALID;
        }
        
        $addon = Upkeep::getAddon();
        $configKey = $target . '_active';
        $currentState = (bool) $addon->getConfig($configKey);
        $newState = $state === 'on';
        
        // Wenn aktueller Status = neuer Status, Warnung ausgeben
        if ($currentState === $newState) {
            $stateText = $newState ? 'aktiviert' : 'deaktiviert';
            $io->warning(sprintf(
                'Der Wartungsmodus für %s ist bereits %s.',
                $target,
                $stateText
            ));
            return Command::SUCCESS;
        }
        
        // Status ändern
        $addon->setConfig($configKey, $newState);
        
        // Erfolg melden
        $stateText = $newState ? 'aktiviert' : 'deaktiviert';
        $io->success(sprintf(
            'Der Wartungsmodus für %s wurde erfolgreich %s.',
            $target,
            $stateText
        ));
        
        return Command::SUCCESS;
    }
}
