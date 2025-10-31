<?php
/**
 * Upkeep AddOn - Security Scan Console Command
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

use FriendsOfRedaxo\Upkeep\SecurityAdvisor;
use rex_console_command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;

class rex_upkeep_security_scan_command extends rex_console_command
{
    protected function configure(): void
    {
        $this->setName('upkeep:security:scan')
             ->setDescription('Führt eine umfassende Sicherheitsprüfung durch')
             ->addOption(
                 'format',
                 'f',
                 InputOption::VALUE_OPTIONAL,
                 'Ausgabeformat (table, json, summary)',
                 'table'
             )
             ->addOption(
                 'output-file',
                 'o',
                 InputOption::VALUE_OPTIONAL,
                 'Datei für die Ausgabe (nur bei json Format)'
             )
             ->addOption(
                 'filter',
                 null,
                 InputOption::VALUE_OPTIONAL,
                 'Filter für Ergebnisse (error, warning, success, all)',
                 'all'
             )
             ->addOption(
                 'silent',
                 's',
                 InputOption::VALUE_NONE,
                 'Keine Fortschrittsanzeige (für Cron-Jobs)'
             );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $format = $input->getOption('format');
        $outputFile = $input->getOption('output-file');
        $filter = $input->getOption('filter');
        $silent = $input->getOption('silent');

        if (!$silent) {
            $output->writeln('<info>Starte Sicherheitsprüfung...</info>');
        }

        $securityAdvisor = new SecurityAdvisor();
        $results = $securityAdvisor->runAllChecks();

        if (!$silent) {
            $output->writeln('<info>Sicherheitsprüfung abgeschlossen.</info>');
        }

        // Ergebnisse filtern
        if ($filter !== 'all') {
            $results['checks'] = array_filter($results['checks'], function($check) use ($filter) {
                return $check['status'] === $filter;
            });
        }

        // Ausgabe je nach Format
        switch ($format) {
            case 'json':
                $this->outputJson($results, $output, $outputFile);
                break;
            case 'summary':
                $this->outputSummary($results, $output);
                break;
            default:
                $this->outputTable($results, $output, $filter);
                break;
        }

        // Exit-Code basierend auf Sicherheitsstatus
        if ($results['summary']['critical_issues'] > 0) {
            return 2; // Kritische Probleme
        } elseif ($results['summary']['warning_issues'] > 0) {
            return 1; // Warnungen
        }
        
        return 0; // Alles OK
    }

    private function outputTable(array $results, OutputInterface $output, string $filter): void
    {
        // Header
        $output->writeln('');
        $output->writeln('<comment>=== SICHERHEITSPRÜFUNG ERGEBNISSE ===</comment>');
        $output->writeln('');
        
        $format = '%-30s %-12s %-8s %-10s %s';
        $output->writeln(sprintf($format, 'CHECK', 'STATUS', 'SCORE', 'SEVERITY', 'BESCHREIBUNG'));
        $output->writeln(str_repeat('-', 100));

        foreach ($results['checks'] as $checkKey => $check) {
            $status = $this->formatStatus($check['status']);
            $severity = strtoupper($check['severity']);
            
            $output->writeln(sprintf($format,
                $this->truncateText($check['name'], 28),
                $status,
                $check['score'] . '/10',
                $severity,
                $this->truncateText($check['description'], 40)
            ));
        }

        // Zusammenfassung
        $this->outputSummary($results, $output);
    }

    private function outputSummary(array $results, OutputInterface $output): void
    {
        $summary = $results['summary'];
        
        $output->writeln('');
        $output->writeln('<comment>=== SICHERHEITSZUSAMMENFASSUNG ===</comment>');
        $output->writeln(sprintf('Gesamtbewertung: <info>%d%% (Note: %s)</info>', 
            $summary['score'], $summary['grade']));
        
        $output->writeln(sprintf('Gesamtprüfungen: <info>%d</info>', $summary['total_checks']));
        
        if ($summary['critical_issues'] > 0) {
            $output->writeln(sprintf('Kritische Probleme: <error>%d</error>', $summary['critical_issues']));
        }
        
        if ($summary['warning_issues'] > 0) {
            $output->writeln(sprintf('Warnungen: <comment>%d</comment>', $summary['warning_issues']));
        }

        $status = match($summary['status']) {
            'success' => '<info>GUT</info>',
            'warning' => '<comment>VERBESSERUNGSBEDARF</comment>',
            'error' => '<error>KRITISCH</error>',
            default => '<comment>UNBEKANNT</comment>'
        };
        
        $output->writeln(sprintf('Status: %s', $status));
        $output->writeln(sprintf('Letzter Scan: <info>%s</info>', 
            date('d.m.Y H:i:s', $results['timestamp'])));

        // Top-Empfehlungen
        $this->outputTopRecommendations($results, $output);
    }

    private function outputTopRecommendations(array $results, OutputInterface $output): void
    {
        $recommendations = [];
        
        foreach ($results['checks'] as $check) {
            if ($check['status'] === 'error' && !empty($check['recommendations'])) {
                foreach ($check['recommendations'] as $rec) {
                    $recommendations[] = [
                        'text' => $rec,
                        'check' => $check['name'],
                        'severity' => $check['severity']
                    ];
                }
            }
        }

        if (!empty($recommendations)) {
            $output->writeln('');
            $output->writeln('<comment>=== TOP-EMPFEHLUNGEN ===</comment>');
            
            // Nach Severity sortieren
            usort($recommendations, function($a, $b) {
                $weights = ['high' => 3, 'medium' => 2, 'low' => 1];
                return ($weights[$b['severity']] ?? 0) <=> ($weights[$a['severity']] ?? 0);
            });

            $count = 1;
            foreach (array_slice($recommendations, 0, 5) as $rec) {
                $severityColor = match($rec['severity']) {
                    'high' => 'error',
                    'medium' => 'comment',
                    'low' => 'info',
                    default => 'info'
                };
                
                $output->writeln(sprintf('%d. <%s>[%s]</> %s', 
                    $count++, $severityColor, strtoupper($rec['severity']), $rec['text']));
            }
        }
    }

    private function outputJson(array $results, OutputInterface $output, ?string $outputFile): void
    {
        $json = json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        
        if ($outputFile) {
            file_put_contents($outputFile, $json);
            $output->writeln(sprintf('<info>Bericht gespeichert: %s</info>', $outputFile));
        } else {
            $output->writeln($json);
        }
    }

    private function formatStatus(string $status): string
    {
        return match($status) {
            'success' => '✓ OK',
            'warning' => '⚠ WARNING',
            'error' => '✗ ERROR',
            'info' => 'ℹ INFO',
            default => '? UNKNOWN'
        };
    }

    private function truncateText(string $text, int $length): string
    {
        return strlen($text) > $length ? substr($text, 0, $length) . '...' : $text;
    }
}