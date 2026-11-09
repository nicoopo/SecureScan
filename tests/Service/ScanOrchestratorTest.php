<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Fix;
use App\Entity\Project;
use App\Entity\Scan;
use App\Service\Analyzer\A010Analyzer;
use App\Service\Analyzer\A01Analyzer;
use App\Service\Analyzer\A02Analyzer;
use App\Service\Analyzer\A03Analyzer;
use App\Service\Analyzer\A04Analyzer;
use App\Service\Analyzer\A05Analyzer;
use App\Service\Analyzer\A06Analyzer;
use App\Service\Analyzer\A07Analyzer;
use App\Service\Analyzer\A08Analyzer;
use App\Service\Analyzer\A09Analyzer;
use App\Service\Analyzer\SemgrepAnalyzer;
use App\Service\FixGeneratorService;
use App\Service\ProjectCloner;
use App\Service\ScanOrchestrator;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Les 11 analyseurs, le cloner et le fix generator sont mockés une fois dans setUp()
 * et servent la plupart du temps de simples stubs (`->method(...)->willReturn(...)`) :
 * chaque test ne vérifie explicitement (`expects(...)`) que les collaborateurs
 * pertinents pour son scénario, pas l'exhaustivité des 15 dépendances.
 */
#[AllowMockObjectsWithoutExpectations]
class ScanOrchestratorTest extends TestCase
{
    private A01Analyzer&MockObject $a01;
    private A02Analyzer&MockObject $a02;
    private A03Analyzer&MockObject $a03;
    private A04Analyzer&MockObject $a04;
    private A05Analyzer&MockObject $a05;
    private A06Analyzer&MockObject $a06;
    private A07Analyzer&MockObject $a07;
    private A08Analyzer&MockObject $a08;
    private A09Analyzer&MockObject $a09;
    private A010Analyzer&MockObject $a010;
    private SemgrepAnalyzer&MockObject $semgrep;

    /** @var array<object&MockObject> */
    private array $analyzers;

    private ProjectCloner&MockObject $cloner;
    private FixGeneratorService&MockObject $fixGenerator;
    private EntityManagerInterface&MockObject $em;
    private LoggerInterface&MockObject $logger;

    private ScanOrchestrator $orchestrator;

    /** @var string[] */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        $this->a01     = $this->createMock(A01Analyzer::class);
        $this->a02     = $this->createMock(A02Analyzer::class);
        $this->a03     = $this->createMock(A03Analyzer::class);
        $this->a04     = $this->createMock(A04Analyzer::class);
        $this->a05     = $this->createMock(A05Analyzer::class);
        $this->a06     = $this->createMock(A06Analyzer::class);
        $this->a07     = $this->createMock(A07Analyzer::class);
        $this->a08     = $this->createMock(A08Analyzer::class);
        $this->a09     = $this->createMock(A09Analyzer::class);
        $this->a010    = $this->createMock(A010Analyzer::class);
        $this->semgrep = $this->createMock(SemgrepAnalyzer::class);

        $this->analyzers = [
            $this->a01, $this->a02, $this->a03, $this->a04, $this->a05,
            $this->a06, $this->a07, $this->a08, $this->a09, $this->a010, $this->semgrep,
        ];

        $this->cloner       = $this->createMock(ProjectCloner::class);
        $this->fixGenerator = $this->createMock(FixGeneratorService::class);
        $this->em           = $this->createMock(EntityManagerInterface::class);
        $this->logger       = $this->createMock(LoggerInterface::class);

        $this->orchestrator = new ScanOrchestrator(
            $this->a01, $this->a02, $this->a03, $this->a04, $this->a05,
            $this->a06, $this->a07, $this->a08, $this->a09, $this->a010, $this->semgrep,
            $this->cloner, $this->fixGenerator, $this->em, $this->logger,
        );
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            @rmdir($dir);
        }
        $this->tempDirs = [];
    }

    public function testDoesNotCloneWhenLocalPathAlreadyExistsOnDisk(): void
    {
        $existingDir = $this->createTempDir();
        $scan        = $this->buildScan($existingDir);
        $this->stubAllAnalyzersReturnEmpty();

        $this->cloner->expects($this->never())->method('clone');
        $this->cloner->expects($this->once())->method('detectLanguage')->with($existingDir)->willReturn('php');

        $this->orchestrator->run($scan);

        $this->assertSame('php', $scan->getProject()->getLanguage());
        $this->assertSame(Scan::STATUS_DONE, $scan->getStatus());
    }

    public function testClonesWhenLocalPathIsNull(): void
    {
        $clonedDir = $this->createTempDir();
        $scan      = $this->buildScan(null);
        $this->stubAllAnalyzersReturnEmpty();

        $this->cloner->expects($this->once())->method('clone')->with($scan->getProject())->willReturn($clonedDir);
        $this->cloner->method('detectLanguage')->willReturn('php');

        $this->orchestrator->run($scan);

        $this->assertSame($clonedDir, $scan->getProject()->getLocalPath());
        $this->assertSame(Scan::STATUS_DONE, $scan->getStatus());
    }

    public function testClonesWhenLocalPathPointsToAMissingDirectory(): void
    {
        $clonedDir = $this->createTempDir();
        $scan      = $this->buildScan(sys_get_temp_dir() . '/securescan_missing_' . bin2hex(random_bytes(6)));
        $this->stubAllAnalyzersReturnEmpty();

        $this->cloner->expects($this->once())->method('clone')->willReturn($clonedDir);
        $this->cloner->method('detectLanguage')->willReturn('php');

        $this->orchestrator->run($scan);

        $this->assertSame($clonedDir, $scan->getProject()->getLocalPath());
        $this->assertSame(Scan::STATUS_DONE, $scan->getStatus());
    }

    public function testFailsScanAndSkipsAnalyzersWhenClonedPathIsStillMissing(): void
    {
        $unusablePath = sys_get_temp_dir() . '/securescan_never_created_' . bin2hex(random_bytes(6));
        $scan         = $this->buildScan(null);

        $this->cloner->expects($this->once())->method('clone')->willReturn($unusablePath);
        $this->a01->expects($this->never())->method('analyze');
        $this->semgrep->expects($this->never())->method('analyze');
        $this->fixGenerator->expects($this->never())->method('generate');
        $this->logger->expects($this->once())->method('warning');

        $this->orchestrator->run($scan);

        $this->assertSame(Scan::STATUS_FAILED, $scan->getStatus());
        $this->assertStringContainsString($unusablePath, (string) $scan->getErrorMessage());
    }

    public function testAggregatesFindingsFromAllAnalyzersPersistsFixesAndMarksScanDone(): void
    {
        $scan = $this->buildScan($this->createTempDir());

        $findingA = $this->buildFinding();
        $findingB = $this->buildFinding();
        $findingC = $this->buildFinding();

        $this->a01->method('analyze')->willReturn([$findingA]);
        $this->a05->method('analyze')->willReturn([$findingB, $findingC]);
        foreach ([$this->a02, $this->a03, $this->a04, $this->a06, $this->a07, $this->a08, $this->a09, $this->a010, $this->semgrep] as $analyzer) {
            $analyzer->method('analyze')->willReturn([]);
        }
        $this->cloner->method('detectLanguage')->willReturn('php');

        $this->fixGenerator->expects($this->exactly(3))
            ->method('generate')
            ->willReturnOnConsecutiveCalls(new Fix(), new Fix(), new Fix());

        $this->em->expects($this->exactly(6))->method('persist'); // 3 findings + 3 fixes

        $this->logger->expects($this->once())
            ->method('info')
            ->with($this->anything(), $this->callback(static fn (array $context) => $context['count'] === 3));

        $this->orchestrator->run($scan);

        $this->assertCount(3, $scan->getFindings());
        $this->assertSame(Scan::STATUS_DONE, $scan->getStatus());
    }

    public function testCatchesAnalyzerExceptionAndFailsScanWithoutPersistingAnything(): void
    {
        $scan = $this->buildScan($this->createTempDir());

        $this->a01->method('analyze')->willThrowException(new \RuntimeException('boom'));
        $this->a02->expects($this->never())->method('analyze');
        $this->cloner->method('detectLanguage')->willReturn('php');

        $this->em->expects($this->never())->method('persist');
        $this->logger->expects($this->once())->method('error');

        $this->orchestrator->run($scan);

        $this->assertSame(Scan::STATUS_FAILED, $scan->getStatus());
        $this->assertSame('boom', $scan->getErrorMessage());
    }

    private function stubAllAnalyzersReturnEmpty(): void
    {
        foreach ($this->analyzers as $analyzer) {
            $analyzer->method('analyze')->willReturn([]);
        }
    }

    private function buildScan(?string $localPath): Scan
    {
        $project = new Project();
        if ($localPath !== null) {
            $project->setLocalPath($localPath);
        }

        $scan = new Scan();
        $scan->setProject($project);

        return $scan;
    }

    private function buildFinding(): Finding
    {
        $finding = new Finding();
        $finding
            ->setTool('securescan')
            ->setSeverity(Finding::SEVERITY_HIGH)
            ->setOwaspCategory(Finding::OWASP_A01)
            ->setTitle('Test finding');

        return $finding;
    }

    private function createTempDir(): string
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;

        return $dir;
    }
}