<?php
/**
 * Upkeep AddOn - Security Advisor Dashboard
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

use KLXM\Upkeep\SecurityAdvisor;

$addon = rex_addon::get('upkeep');
$securityAdvisor = new SecurityAdvisor();

// Aktion verarbeiten
$action = rex_request::get('action', 'string', '');
$message = '';

if ($action === 'run_scan' && $_POST) {
    $results = $securityAdvisor->runAllChecks();
    $message = rex_view::success($addon->i18n('upkeep_security_scan_completed'));
}

// Dashboard-Statistiken laden
$stats = $securityAdvisor->getDashboardStats();


if ($message) {
    echo $message;
}

// Gesamtbewertung anzeigen
$gradeClass = match($stats['security_grade']) {
    'A+', 'A' => 'success',
    'B', 'C' => 'warning', 
    default => 'danger'
};

$statusIcon = match($stats['overall_status']) {
    'success' => 'check-circle',
    'warning' => 'exclamation-triangle',
    default => 'times-circle'
};

?>

<div class="row">
    <div class="col-md-4">
        <div class="panel panel-<?= $gradeClass ?>">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-shield"></i> 
                    <?= $addon->i18n('upkeep_security_score') ?>
                </h3>
            </div>
            <div class="panel-body text-center">
                <div class="security-score">
                    <div class="score-circle">
                        <span class="score-number"><?= $stats['security_score'] ?>%</span>
                        <span class="score-grade"><?= $stats['security_grade'] ?></span>
                    </div>
                </div>
                <p class="security-status">
                    <i class="rex-icon fa fa-<?= $statusIcon ?>"></i>
                    <?= $addon->i18n('upkeep_security_status_' . $stats['overall_status']) ?>
                </p>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-exclamation-triangle"></i> 
                    <?= $addon->i18n('upkeep_security_issues') ?>
                </h3>
            </div>
            <div class="panel-body">
                <div class="security-stats">
                    <div class="stat-item">
                        <span class="stat-number text-danger"><?= $stats['critical_issues'] ?></span>
                        <span class="stat-label"><?= $addon->i18n('upkeep_critical_issues') ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number text-warning"><?= $stats['warning_issues'] ?></span>
                        <span class="stat-label"><?= $addon->i18n('upkeep_warning_issues') ?></span>
                    </div>
                </div>
                
                <?php if ($stats['critical_issues'] > 0): ?>
                    <div class="alert alert-danger alert-sm">
                        <i class="rex-icon fa fa-exclamation-triangle"></i>
                        <?= $addon->i18n('upkeep_critical_issues_warning') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-clock-o"></i> 
                    <?= $addon->i18n('upkeep_last_scan') ?>
                </h3>
            </div>
            <div class="panel-body">
                <p class="last-scan-time">
                    <?php if ($stats['last_check']): ?>
                        <?= date('d.m.Y H:i:s', $stats['last_check']) ?>
                    <?php else: ?>
                        <?= $addon->i18n('upkeep_never_scanned') ?>
                    <?php endif; ?>
                </p>
                
                <div class="scan-actions">
                    <form method="post" style="display: inline-block;">
                        <input type="hidden" name="action" value="run_scan">
                        <button type="submit" class="btn btn-primary">
                            <i class="rex-icon fa fa-refresh"></i> 
                            <?= $addon->i18n('upkeep_run_security_scan') ?>
                        </button>
                    </form>
                    
                    <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports') ?>" class="btn btn-default">
                        <i class="rex-icon fa fa-list"></i> 
                        <?= $addon->i18n('upkeep_detailed_report') ?>
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<?php if ($stats['last_check']): ?>
<!-- Quick Overview of the most important checks -->
<div class="row">
    <div class="col-md-12">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-tachometer"></i> 
                    <?= $addon->i18n('upkeep_security_overview') ?>
                </h3>
            </div>
            <div class="panel-body">
                <?php
                $results = $securityAdvisor->runAllChecks();
                $quickChecks = [
                    'live_mode' => $addon->i18n('upkeep_check_live_mode'),
                    'ssl_certificates' => $addon->i18n('upkeep_check_ssl_certificates'),
                    'server_headers' => $addon->i18n('upkeep_check_server_headers'),
                    'database_security' => $addon->i18n('upkeep_check_database_security')
                ];
                ?>
                
                <div class="row">
                    <?php foreach ($quickChecks as $checkKey => $checkName): ?>
                        <?php if (isset($results['checks'][$checkKey])): ?>
                            <?php $check = $results['checks'][$checkKey]; ?>
                            <div class="col-md-3">
                                <div class="quick-check-item">
                                    <div class="check-status check-<?= $check['status'] ?>">
                                        <i class="rex-icon fa fa-<?= getStatusIcon($check['status']) ?>"></i>
                                    </div>
                                    <div class="check-info">
                                        <h5><?= $checkName ?></h5>
                                        <span class="check-score"><?= $check['score'] ?>/10</span>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Top Recommendations -->
<div class="row">
    <div class="col-md-12">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-lightbulb-o"></i> 
                    <?= $addon->i18n('upkeep_top_recommendations') ?>
                </h3>
            </div>
            <div class="panel-body">
                <?php
                $allRecommendations = [];
                foreach ($results['checks'] as $check) {
                    if ($check['status'] === 'error' && !empty($check['recommendations'])) {
                        foreach ($check['recommendations'] as $rec) {
                            $allRecommendations[] = [
                                'text' => $rec,
                                'severity' => $check['severity'],
                                'check' => $check['name']
                            ];
                        }
                    }
                }
                
                // Sort top 5 recommendations by severity
                usort($allRecommendations, function($a, $b) {
                    $weights = ['high' => 3, 'medium' => 2, 'low' => 1];
                    return ($weights[$b['severity']] ?? 0) <=> ($weights[$a['severity']] ?? 0);
                });
                
                $topRecommendations = array_slice($allRecommendations, 0, 5);
                ?>
                
                <?php if (empty($topRecommendations)): ?>
                    <div class="alert alert-success">
                        <i class="rex-icon fa fa-check-circle"></i>
                        <?= $addon->i18n('upkeep_no_critical_recommendations') ?>
                    </div>
                <?php else: ?>
                    <ul class="recommendation-list">
                        <?php foreach ($topRecommendations as $rec): ?>
                            <li class="recommendation-item severity-<?= $rec['severity'] ?>">
                                <i class="rex-icon fa fa-<?= $rec['severity'] === 'high' ? 'exclamation-triangle' : 'warning' ?>"></i>
                                <strong><?= $rec['check'] ?>:</strong> <?= $rec['text'] ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<style>
.security-score {
    margin: 20px 0;
}

.score-circle {
    display: inline-block;
    padding: 20px;
    border-radius: 50%;
    background: rgba(255,255,255,0.1);
    min-width: 120px;
    min-height: 120px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.score-number {
    font-size: 2.5em;
    font-weight: bold;
    display: block;
}

.score-grade {
    font-size: 1.2em;
    opacity: 0.8;
}

.security-stats {
    display: flex;
    justify-content: space-around;
    margin-bottom: 15px;
}

.stat-item {
    text-align: center;
}

.stat-number {
    display: block;
    font-size: 2em;
    font-weight: bold;
}

.stat-label {
    font-size: 0.9em;
    opacity: 0.7;
}

.scan-actions {
    margin-top: 15px;
}

.scan-actions .btn {
    margin-right: 10px;
}

.quick-check-item {
    display: flex;
    align-items: center;
    padding: 15px;
    border: 1px solid #e5e5e5;
    border-radius: 5px;
    margin-bottom: 10px;
}

.check-status {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 15px;
    font-size: 1.2em;
}

.check-status.check-success {
    background-color: #d4edda;
    color: #155724;
}

.check-status.check-warning {
    background-color: #fff3cd;
    color: #856404;
}

.check-status.check-error {
    background-color: #f8d7da;
    color: #721c24;
}

.check-status.check-info {
    background-color: #d1ecf1;
    color: #0c5460;
}

.check-info h5 {
    margin: 0 0 5px 0;
    font-size: 0.9em;
}

.check-score {
    font-size: 0.8em;
    opacity: 0.7;
}

.recommendation-list {
    list-style: none;
    padding: 0;
}

.recommendation-item {
    padding: 10px;
    margin-bottom: 8px;
    border-left: 4px solid #ddd;
    background: #f9f9f9;
}

.recommendation-item.severity-high {
    border-left-color: #dc3545;
}

.recommendation-item.severity-medium {
    border-left-color: #ffc107;
}

.recommendation-item.severity-low {
    border-left-color: #28a745;
}

.last-scan-time {
    font-size: 1.1em;
    margin-bottom: 15px;
}

.alert-sm {
    padding: 8px 12px;
    font-size: 0.9em;
    margin-top: 10px;
}
</style>

<?php
// Helper-Funktion für Status-Icons
function getStatusIcon($status) {
    return match($status) {
        'success' => 'check-circle',
        'warning' => 'exclamation-triangle',
        'error' => 'times-circle',
        'info' => 'info-circle',
        default => 'question-circle'
    };
}
?>