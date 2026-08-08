<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\ChartService;
use PHPUnit\Framework\TestCase;
use Symfony\UX\Chartjs\Builder\ChartBuilder;
use Symfony\UX\Chartjs\Model\Chart;

class ChartServiceTest extends TestCase
{
    private ChartService $service;

    protected function setUp(): void
    {
        // ChartBuilder est une simple fabrique sans dépendance : pas besoin de mock.
        $this->service = new ChartService(new ChartBuilder());
    }

    public function testSeverityChartCountsFindingsPerSeverityInFixedOrder(): void
    {
        $scan = new Scan();
        $this->addFindings($scan, [
            Finding::SEVERITY_CRITICAL,
            Finding::SEVERITY_CRITICAL,
            Finding::SEVERITY_HIGH,
            Finding::SEVERITY_LOW,
            Finding::SEVERITY_LOW,
            Finding::SEVERITY_LOW,
        ]);

        $chart = $this->service->buildSeverityChart($scan);

        $this->assertSame(Chart::TYPE_DOUGHNUT, $chart->getType());
        $data = $chart->getData();
        $this->assertSame(['Critique', 'Haute', 'Moyenne', 'Basse'], $data['labels']);
        // Ordre fixe : critical, high, medium, low — indépendant de l'ordre d'ajout des findings.
        $this->assertSame([2, 1, 0, 3], $data['datasets'][0]['data']);
        $this->assertSame(['#ef4444', '#f97316', '#3b82f6', '#22c55e'], $data['datasets'][0]['backgroundColor']);
    }

    public function testSeverityChartWithNoFindingsIsAllZero(): void
    {
        $chart = $this->service->buildSeverityChart(new Scan());

        $this->assertSame([0, 0, 0, 0], $chart->getData()['datasets'][0]['data']);
    }

    public function testSeverityChartExposesBottomLegendOptions(): void
    {
        $chart = $this->service->buildSeverityChart(new Scan());

        $legend = $chart->getOptions()['plugins']['legend'];
        $this->assertTrue($legend['display']);
        $this->assertSame('bottom', $legend['position']);
    }

    public function testOwaspChartCoversAllTenCategoriesInCanonicalOrderWithZeroDefaults(): void
    {
        $scan = new Scan();
        $this->addFindings($scan, [], owaspCategories: [Finding::OWASP_A01, Finding::OWASP_A01, Finding::OWASP_A05]);

        $chart = $this->service->buildOwaspChart($scan);

        $this->assertSame(Chart::TYPE_BAR, $chart->getType());
        $data = $chart->getData();
        $this->assertSame(array_keys(Finding::OWASP_LABELS), $data['labels']);

        $expected = array_fill_keys(array_keys(Finding::OWASP_LABELS), 0);
        $expected[Finding::OWASP_A01] = 2;
        $expected[Finding::OWASP_A05] = 1;
        $this->assertSame(array_values($expected), $data['datasets'][0]['data']);
    }

    public function testOwaspChartWithNoFindingsDefaultsEveryCategoryToZero(): void
    {
        $chart = $this->service->buildOwaspChart(new Scan());

        $this->assertSame(array_fill(0, 10, 0), $chart->getData()['datasets'][0]['data']);
    }

    public function testDoughnutHelperBuildsExpectedStructure(): void
    {
        $chart = $this->service->doughnut(
            labels: ['A', 'B'],
            data: [3, 7],
            colors: ['#111111', '#222222'],
            options: ['foo' => 'bar']
        );

        $this->assertSame(Chart::TYPE_DOUGHNUT, $chart->getType());
        $this->assertSame(['A', 'B'], $chart->getData()['labels']);
        $this->assertSame([3, 7], $chart->getData()['datasets'][0]['data']);
        $this->assertSame(['#111111', '#222222'], $chart->getData()['datasets'][0]['backgroundColor']);
        $this->assertSame(0, $chart->getData()['datasets'][0]['borderWidth']);
        $this->assertSame(['foo' => 'bar'], $chart->getOptions());
    }

    public function testCreateHelperBuildsAChartOfTheRequestedType(): void
    {
        $chart = $this->service->create(
            type: Chart::TYPE_LINE,
            labels: ['Jan', 'Feb'],
            datasets: [['label' => 'Scans', 'data' => [1, 4]]]
        );

        $this->assertSame(Chart::TYPE_LINE, $chart->getType());
        $this->assertSame(['label' => 'Scans', 'data' => [1, 4]], $chart->getData()['datasets'][0]);
    }

    /**
     * `$isDark` est un paramètre accepté par toutes les méthodes publiques mais
     * jamais lu dans `create()` : il n'a aujourd'hui aucun effet sur les données ou
     * options produites. Comportement réel documenté ici plutôt que supposé —
     * si un jour le thème doit influencer les couleurs, ce test doit être mis à jour.
     */
    public function testIsDarkFlagCurrentlyHasNoEffectOnChartOutput(): void
    {
        $scan = new Scan();
        $this->addFindings($scan, [Finding::SEVERITY_HIGH]);

        $light = $this->service->buildSeverityChart($scan, isDark: false);
        $dark   = $this->service->buildSeverityChart($scan, isDark: true);

        $this->assertSame($light->getData(), $dark->getData());
        $this->assertSame($light->getOptions(), $dark->getOptions());
    }

    /**
     * @param string[] $severities
     * @param string[] $owaspCategories
     */
    private function addFindings(Scan $scan, array $severities = [], array $owaspCategories = []): void
    {
        foreach ($severities as $severity) {
            $finding = new Finding();
            $finding
                ->setTool('securescan')
                ->setSeverity($severity)
                ->setOwaspCategory(Finding::OWASP_A01)
                ->setTitle('Test finding');
            $scan->addFinding($finding);
        }

        foreach ($owaspCategories as $category) {
            $finding = new Finding();
            $finding
                ->setTool('securescan')
                ->setSeverity(Finding::SEVERITY_LOW)
                ->setOwaspCategory($category)
                ->setTitle('Test finding');
            $scan->addFinding($finding);
        }
    }
}