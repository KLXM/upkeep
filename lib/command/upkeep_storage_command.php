<?php

use KLXM\Upkeep\Storage;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Berechnet die Speicherübersicht neu (upkeep:storage).
 */
class rex_upkeep_storage_command extends rex_console_command
{
    protected function configure(): void
    {
        $this
            ->setName('upkeep:storage')
            ->setDescription('Recalculates the storage overview and stores it in the cache')
            ->addOption('budget', 'b', InputOption::VALUE_REQUIRED, 'Time limit in seconds', (string) Storage::DEFAULT_TIME_BUDGET)
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the report as JSON');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $budget = max(1.0, (float) $input->getOption('budget'));

        $report = Storage::refresh($budget);
        if ([] === $report) {
            $io->error('Another calculation is running.');
            return self::FAILURE;
        }

        if ($input->getOption('json')) {
            $output->writeln((string) json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            return self::SUCCESS;
        }

        $rows = [];
        foreach ($report['categories'] as $cat) {
            $rows[] = [
                $cat['key'],
                rex_formatter::bytes((int) $cat['bytes'], [1]),
                $cat['count'],
                !empty($cat['partial']) ? 'partial' : '',
            ];
        }
        $io->table(['Category', 'Size', 'Count', ''], $rows);
        $io->writeln(sprintf('Total: <info>%s</info>', rex_formatter::bytes((int) $report['total_bytes'], [1])));
        if (is_array($report['disk'] ?? null)) {
            $io->writeln(sprintf('Disk: %s free of %s', rex_formatter::bytes($report['disk']['free'], [1]), rex_formatter::bytes($report['disk']['total'], [1])));
        }
        if (!empty($report['media']['missing'])) {
            $io->warning(sprintf('%d mediapool files are missing on disk.', $report['media']['missing']));
        }
        $io->writeln(sprintf('Duration: %.2f s', $report['duration']));

        if (!empty($report['partial'])) {
            $io->warning('Time limit reached, report is partial.');
        } else {
            $io->success('Storage report updated.');
        }

        return self::SUCCESS;
    }
}
