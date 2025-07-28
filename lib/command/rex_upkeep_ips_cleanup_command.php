<?php

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use KLXM\Upkeep\IntrusionPrevention;

/**
 * Konsolen-Kommando für IPS-Bereinigung
 */
class rex_upkeep_ips_cleanup_command extends rex_console_command
{
    protected function configure(): void
    {
        $this
            ->setName('upkeep:ips:cleanup')
            ->setDescription('Bereinigt abgelaufene IP-Sperrungen und alte Logs des Intrusion Prevention Systems');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>Starte IPS-Bereinigung...</info>');
        
        $results = IntrusionPrevention::cleanupExpiredData();
        
        $output->writeln('');
        $output->writeln('<info>Bereinigung abgeschlossen:</info>');
        $output->writeln(sprintf('  - Abgelaufene IP-Sperrungen gelöscht: <comment>%d</comment>', $results['expired_ips']));
        $output->writeln(sprintf('  - Alte Bedrohungs-Logs gelöscht: <comment>%d</comment>', $results['old_threats']));
        $output->writeln(sprintf('  - Alte Rate-Limit-Daten gelöscht: <comment>%d</comment>', $results['old_rate_limits']));
        
        if ($results['expired_ips'] > 0 || $results['old_threats'] > 0 || $results['old_rate_limits'] > 0) {
            $output->writeln('');
            $output->writeln('<success>Datenbank erfolgreich bereinigt!</success>');
        } else {
            $output->writeln('');
            $output->writeln('<comment>Keine Bereinigung notwendig - alle Daten sind aktuell.</comment>');
        }
        
        return self::SUCCESS;
    }
}
