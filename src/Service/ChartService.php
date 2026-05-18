<?php

namespace App\Service;

use App\Entity\Finding;
use App\Entity\Scan;
use Symfony\UX\Chartjs\Builder\ChartBuilderInterface;
use Symfony\UX\Chartjs\Model\Chart;

class ChartService
{
    public function __construct(
        private ChartBuilderInterface $chartBuilder,
    ) {}

    // -------------------------------------------------------------------------
    // Charts métier
    // -------------------------------------------------------------------------

    public function buildSeverityChart(Scan $scan, bool $isDark = false): Chart
    {
        $counts = $scan->countBySeverity();

        return $this->doughnut(
            labels:  ['Critique', 'Haute', 'Moyenne', 'Basse'],
            data:    [
                $counts[Finding::SEVERITY_CRITICAL],
                $counts[Finding::SEVERITY_HIGH],
                $counts[Finding::SEVERITY_MEDIUM],
                $counts[Finding::SEVERITY_LOW],
            ],
            colors:  ['#ef4444', '#f97316', '#3b82f6', '#22c55e'],
            options: [
                'plugins' => [
                    'legend' => [
                        'display'  => true,
                        'position' => 'bottom',
                        'labels'   => [
                            'usePointStyle' => true,
                            'boxWidth'      => 8,
                            'padding'       => 20,
                            'font'          => ['size' => 11],
                        ],
                    ],
                ],
            ],
            isDark:  $isDark,
        );
    }

    public function buildOwaspChart(Scan $scan, bool $isDark = false): Chart
    {
        $counts = $scan->countByOwasp();
        $labels = array_keys(Finding::OWASP_LABELS);

        return $this->create(
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
                'plugins' => [
                    'legend' => [
                        'display'  => true,
                        'position' => 'bottom',
                        'labels'   => [
                            'usePointStyle' => true,
                            'boxWidth'      => 8,
                            'padding'       => 20,
                        ],
                    ],
                ],
            ],
            isDark: $isDark,
        );
    }

    // -------------------------------------------------------------------------
    // Helpers génériques
    // -------------------------------------------------------------------------

    public function doughnut(array $labels, array $data, array $colors, array $options = [], bool $isDark = false): Chart
    {
        return $this->create(
            type:     Chart::TYPE_DOUGHNUT,
            labels:   $labels,
            datasets: [[
                'data'            => $data,
                'backgroundColor' => $colors,
                'borderWidth'     => 0,
            ]],
            options: $options,
            isDark:  $isDark,
        );
    }

    public function create(string $type, array $labels, array $datasets, array $options = [], bool $isDark = false): Chart
    {
        $chart = $this->chartBuilder->createChart($type);
        $chart->setData(['labels' => $labels, 'datasets' => $datasets]);
        $chart->setOptions($options);
        return $chart;
    }
}
