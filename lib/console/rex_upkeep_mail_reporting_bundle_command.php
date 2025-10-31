<?php
/**
 * Upkeep AddOn - Mail Reporting Console Command
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

use FriendsOfRedaxo\Upkeep\MailReporting;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class rex_upkeep_mail_reporting_bundle_command extends rex_console_command
{
    protected function configure(): void
    {
        $this
            ->setName('upkeep:mail-reporting:send-bundle')
            ->setDescription('Send bundled Upkeep reports via email')
            ->addOption('interval', 'i', InputOption::VALUE_OPTIONAL, 'Time interval in seconds for bundling reports', 3600)
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Force sending even if mail reporting is disabled')
            ->addOption('test', 't', InputOption::VALUE_NONE, 'Send test email instead of bundle')
            ->setHelp('This command sends bundled reports from Upkeep Mail Reporting system');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getStyle($input, $output);
        
        // Check if mail reporting is enabled
        if (!MailReporting::isEnabled() && !$input->getOption('force')) {
            $io->error('Mail reporting is disabled. Use --force to send anyway.');
            return 1;
        }
        
        if ($input->getOption('test')) {
            return $this->sendTestEmail($io);
        }
        
        return $this->sendBundleReport($input, $io);
    }
    
    private function sendTestEmail($io): int
    {
        $io->text('Sending test email...');
        
        try {
            if (MailReporting::sendStatusReport()) {
                $io->success('Test email sent successfully to: ' . MailReporting::getEmail());
                return 0;
            } else {
                $io->error('Failed to send test email. Check your mail configuration.');
                return 1;
            }
        } catch (Exception $e) {
            $io->error('Error sending test email: ' . $e->getMessage());
            return 1;
        }
    }
    
    private function sendBundleReport(InputInterface $input, $io): int
    {
        $interval = (int) $input->getOption('interval');
        
        if ($interval < 300) {
            $io->error('Interval must be at least 300 seconds (5 minutes)');
            return 1;
        }
        
        $io->text("Collecting reports from the last {$interval} seconds...");
        
        $logFiles = MailReporting::getLogFiles();
        $fromTime = time() - $interval;
        $relevantFiles = [];
        
        foreach ($logFiles as $file) {
            $parts = explode('_', $file);
            if (isset($parts[0]) && is_numeric($parts[0]) && $parts[0] > $fromTime) {
                $relevantFiles[] = $file;
            }
        }
        
        if (empty($relevantFiles)) {
            $io->text('No reports found for the specified interval.');
            return 0;
        }
        
        $io->text('Found ' . count($relevantFiles) . ' reports to send.');
        
        // Group by type for summary
        $typeCount = [];
        foreach ($relevantFiles as $file) {
            $parts = explode('_', $file);
            if (isset($parts[1])) {
                $type = str_replace('.log.json', '', $parts[1]);
                $typeCount[$type] = ($typeCount[$type] ?? 0) + 1;
            }
        }
        
        $io->text('Report breakdown:');
        foreach ($typeCount as $type => $count) {
            $io->text("  - {$type}: {$count}");
        }
        
        try {
            if (MailReporting::sendBundleReport($interval)) {
                $io->success('Bundle report sent successfully to: ' . MailReporting::getEmail());
                $io->text('Log files have been cleaned up.');
                return 0;
            } else {
                $io->error('Failed to send bundle report. Check your mail configuration.');
                return 1;
            }
        } catch (Exception $e) {
            $io->error('Error sending bundle report: ' . $e->getMessage());
            return 1;
        }
    }
}