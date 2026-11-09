<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Fix;
use App\Entity\Project;
use App\Entity\Scan;
use App\Entity\ScanReport;
use App\Service\ReportGeneratorService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

/**
 * Rend le vrai template `report/pdf.html.twig` avec un `Twig\Environment` autonome
 * (pas besoin du bridge Symfony : le template n'utilise que des filtres Twig core)
 * et un vrai Dompdf (déjà une dépendance réelle du projet) — seuls l'EntityManager
 * et le ParameterBag sont mockés.
 */
#[AllowMockObjectsWithoutExpectations]
class ReportGeneratorServiceTest extends TestCase
{
    private EntityManagerInterface&MockObject $em;
    private ParameterBagInterface&MockObject $params;
    private ReportGeneratorService $service;
    private string $projectDir;

    protected function setUp(): void
    {
        $this->em     = $this->createMock(EntityManagerInterface::class);
        $this->params = $this->createMock(ParameterBagInterface::class);
        $this->projectDir = sys_get_temp_dir() . '/securescan_report_' . bin2hex(random_bytes(8));
        mkdir($this->projectDir, 0777, true);
        $this->params->method('get')->willReturn($this->projectDir);

        $twig = new Environment(new FilesystemLoader(dirname(__DIR__, 2) . '/templates'));

        $this->service = new ReportGeneratorService($twig, $this->em, $this->params);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->projectDir);
    }

    public function testGeneratesAPdfFileAndPersistsANewScanReport(): void
    {
        $scan = $this->buildScan();

        $this->em->expects($this->once())->method('persist')->with($this->isInstanceOf(ScanReport::class));
        $this->em->expects($this->once())->method('flush');

        $pdfContent = $this->service->generate($scan);

        $this->assertStringStartsWith('%PDF-', $pdfContent);
        $this->assertNotNull($scan->getReport());
        $this->assertSame($scan, $scan->getReport()->getScan());
        $this->assertStringStartsWith('/reports/report_scan_', $scan->getReport()->getPdfPath());

        $savedPath = $this->projectDir . '/public' . $scan->getReport()->getPdfPath();
        $this->assertFileExists($savedPath);
        $this->assertSame($pdfContent, file_get_contents($savedPath));
    }

    public function testReusesTheExistingScanReportOnRegeneration(): void
    {
        $scan = $this->buildScan();
        $this->service->generate($scan);
        $existingReport = $scan->getReport();

        $this->service->generate($scan);

        $this->assertSame($existingReport, $scan->getReport());
    }

    private function buildScan(): Scan
    {
        $project = new Project();
        $project->setRepositoryUrl('https://github.com/acme/demo')->setLanguage('php');

        $scan = new Scan();
        $scan->setProject($project);

        $critical = $this->buildFinding(Finding::SEVERITY_CRITICAL);
        $scan->addFinding($critical);

        $fixed = $this->buildFinding(Finding::SEVERITY_HIGH);
        $fix = new Fix();
        $fix->setProposedCode('fixed code')->accept();
        $fixed->addFix($fix);
        $scan->addFinding($fixed);

        return $scan;
    }

    private function buildFinding(string $severity): Finding
    {
        $finding = new Finding();
        $finding
            ->setTool('securescan')
            ->setSeverity($severity)
            ->setOwaspCategory(Finding::OWASP_A05)
            ->setRuleId('a05.injection.sql_raw')
            ->setTitle('Injection SQL')
            ->setDescription('Description de test.')
            ->setFilePath('db.php')
            ->setLine(12);

        return $finding;
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (new \FilesystemIterator($dir) as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir()) {
                $this->removeDirectory($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }
}