<?php

use KLXM\Upkeep\ClientIp;
use KLXM\Upkeep\IntrusionPrevention;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Notausgang: Sperre einer IP aufheben (z. B. wenn ein Admin sich selbst ausgesperrt hat).
 * Das Backend ist für gesperrte Adressen ohne Anmeldung nicht erreichbar – die Konsole schon.
 */
class rex_upkeep_ips_unblock_command extends rex_console_command
{
    protected function configure(): void
    {
        $this
            ->setName('upkeep:ips:unblock')
            ->setDescription('Hebt die IPS-Sperre einer IP-Adresse auf (Notausgang, wenn das Backend gesperrt ist)')
            ->addArgument('ip', InputArgument::REQUIRED, 'IP-Adresse')
            ->addOption('allow', null, InputOption::VALUE_NONE, 'Adresse zusätzlich dauerhaft auf die Positivliste setzen');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $ip = trim((string) $input->getArgument('ip'));
        if (false === filter_var($ip, FILTER_VALIDATE_IP)) {
            $output->writeln('<error>Ungültige IP-Adresse.</error>');
            return self::FAILURE;
        }

        $removed = IntrusionPrevention::unblockIp($ip);
        IntrusionPrevention::clearThreatHistory($ip);
        $output->writeln($removed ? '<info>Sperre aufgehoben: ' . $ip . '</info>' : '<comment>Für ' . $ip . ' bestand keine Sperre.</comment>');

        if ($input->getOption('allow')) {
            $ok = IntrusionPrevention::addToPositivliste($ip, 'Konsole: upkeep:ips:unblock --allow', 'admin');
            $output->writeln($ok ? '<info>Auf die Positivliste gesetzt.</info>' : '<error>Positivliste: Eintrag nicht möglich.</error>');
        }

        $bucket = ClientIp::bucket($ip);
        if ($bucket !== $ip) {
            $output->writeln('<comment>Hinweis: Zähler gelten für das Netz ' . $bucket . '.</comment>');
        }
        return self::SUCCESS;
    }
}
