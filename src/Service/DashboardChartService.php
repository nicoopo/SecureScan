<?php

namespace App\Service;

use App\Entity\Finding;
use App\Entity\Scan;
use Symfony\UX\Chartjs\Model\Chart;

class DashboardChartService
{
    public function __construct(
        private ChartService $chartService,
    ) {}

    public function buildSeverityChart(Scan $scan, bool $isDark = false): Chart
    {
        $counts = $scan->countBySeverity();

        return $this->chartService->doughnut(
            labels: ['Critique', 'Haute', 'Moyenne', 'Basse'],
            data:   [
                $counts[Finding::SEVERITY_CRITICAL],
                $counts[Finding::SEVERITY_HIGH],
                $counts[Finding::SEVERITY_MEDIUM],
                $counts[Finding::SEVERITY_LOW],
            ],
            colors:  ['#ef4444', '#f97316', '#3b82f6', '#22c55e'],
            options: ['plugins' => ['legend' => ['display' => false]]],
            isDark:  $isDark,
        );
    }

    public function buildOwaspChart(Scan $scan, bool $isDark = false): Chart
    {
        $counts = $scan->countByOwasp();
        $labels = array_keys(Finding::OWASP_LABELS);

        return $this->chartService->create(
            type:     Chart::TYPE_BAR,
            labels:   $labels,
            datasets: [[
                'label'           => 'Findings',
                'data'            => array_map(fn($k) => $counts[$k] ?? 0, $labels),
                'backgroundColor' => '#3b82f6',
                'borderRadius'    => 4,
                'borderWidth'     => 0,
            ]],
            options: [
                'indexAxis' => 'y',
                'plugins'   => ['legend' => ['display' => false]],
                'scales'    => [
                    'x' => ['ticks' => ['stepSize' => 1]],
                    'y' => ['grid'  => ['display' => false]],
                ],
            ],
            isDark: $isDark,
        );
    }
}
