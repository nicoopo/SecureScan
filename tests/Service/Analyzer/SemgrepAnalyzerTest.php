<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\SemgrepAnalyzer;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `analyze()` shell_exec un vrai binaire `semgrep`, potentiellement absent (ou lent) de
 * l'environnement de test — cf. la même réserve dans A03AnalyzerTest. On teste donc la
 * logique propre de l'analyseur (parsing du JSON, mapping OWASP/sévérité, lecture du
 * snippet) directement via Reflection sur les méthodes privées, comme pour la logique
 * de GitHubPushService atteignable seulement après un vrai appel réseau.
 */
class SemgrepAnalyzerTest extends AnalyzerTestCase
{
    private SemgrepAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new SemgrepAnalyzer();
    }

    // -------------------------------------------------------------------------
    // buildFinding()
    // -------------------------------------------------------------------------

    public function testBuildFindingMapsSemgrepResultToFinding(): void
    {
        $project = $this->createProject([
            'src/UserController.php' => str_repeat("// filler\n", 41)
                . '        $query = "SELECT * FROM users WHERE id = " . $_GET[\'id\'];' . "\n",
        ]);

        $result = [
            'check_id' => 'php.lang.security.injection.tainted-sql-string',
            'path'     => 'src/UserController.php',
            'start'    => ['line' => 42],
            'extra'    => [
                'message'  => 'User input flows into SQL query without sanitization.',
                'severity' => 'ERROR',
            ],
        ];

        $finding = $this->invokePrivate($this->analyzer, 'buildFinding', [new Scan(), $result, Finding::OWASP_A05, $project]);

        $this->assertSame(Finding::TOOL_SEMGREP, $finding->getTool());
        $this->assertSame(Finding::SEVERITY_HIGH, $finding->getSeverity());
        $this->assertSame(Finding::OWASP_A05, $finding->getOwaspCategory());
        $this->assertSame('php.lang.security.injection.tainted-sql-string', $finding->getRuleId());
        $this->assertSame('User input flows into SQL query without sanitization.', $finding->getTitle());
        $this->assertSame('src/UserController.php', $finding->getFilePath());
        $this->assertSame(42, $finding->getLine());
        $this->assertSame('$query = "SELECT * FROM users WHERE id = " . $_GET[\'id\'];', $finding->getCodeSnippet());
        $this->assertSame($result, $finding->getRawData());
    }

    public function testBuildFindingFallsBackToCheckIdWhenMessageMissing(): void
    {
        $project = $this->createProject(['app.php' => "<?php\n"]);

        $result = [
            'check_id' => 'generic.rule-id',
            'path'     => 'app.php',
            'start'    => ['line' => 1],
            'extra'    => [],
        ];

        $finding = $this->invokePrivate($this->analyzer, 'buildFinding', [new Scan(), $result, Finding::OWASP_A01, $project]);

        $this->assertSame('generic.rule-id', $finding->getTitle());
    }

    public function testBuildFindingTruncatesLongTitleAndRuleId(): void
    {
        $project = $this->createProject(['app.php' => "<?php\n"]);

        $result = [
            'check_id' => str_repeat('r', 300),
            'path'     => 'app.php',
            'start'    => ['line' => 1],
            'extra'    => ['message' => str_repeat('m', 300)],
        ];

        $finding = $this->invokePrivate($this->analyzer, 'buildFinding', [new Scan(), $result, Finding::OWASP_A01, $project]);

        $this->assertSame(255, mb_strlen($finding->getRuleId()));
        $this->assertSame(255, mb_strlen($finding->getTitle()));
    }

    // -------------------------------------------------------------------------
    // extractSnippet() (via buildFinding, seul point d'entrée)
    // -------------------------------------------------------------------------

    public function testCodeSnippetIsEmptyWhenFileMissing(): void
    {
        $project = $this->createProject([]);

        $result = ['check_id' => 'r', 'path' => 'missing.php', 'start' => ['line' => 1], 'extra' => []];
        $finding = $this->invokePrivate($this->analyzer, 'buildFinding', [new Scan(), $result, Finding::OWASP_A01, $project]);

        $this->assertSame('', $finding->getCodeSnippet());
    }

    public function testCodeSnippetIsEmptyWhenLineOutOfRange(): void
    {
        $project = $this->createProject(['app.php' => "line1\nline2\n"]);

        $result = ['check_id' => 'r', 'path' => 'app.php', 'start' => ['line' => 99], 'extra' => []];
        $finding = $this->invokePrivate($this->analyzer, 'buildFinding', [new Scan(), $result, Finding::OWASP_A01, $project]);

        $this->assertSame('', $finding->getCodeSnippet());
    }

    // -------------------------------------------------------------------------
    // mapSeverity()
    // -------------------------------------------------------------------------

    #[DataProvider('severityProvider')]
    public function testMapSeverity(array $result, string $expected): void
    {
        $this->assertSame($expected, $this->invokePrivate($this->analyzer, 'mapSeverity', [$result]));
    }

    public static function severityProvider(): iterable
    {
        yield 'impact HIGH + likelihood HIGH overrides severity field' => [
            ['extra' => ['severity' => 'WARNING', 'metadata' => ['impact' => 'HIGH', 'likelihood' => 'HIGH']]],
            Finding::SEVERITY_CRITICAL,
        ];
        yield 'impact HIGH alone does not trigger critical' => [
            ['extra' => ['severity' => 'ERROR', 'metadata' => ['impact' => 'HIGH', 'likelihood' => 'LOW']]],
            Finding::SEVERITY_HIGH,
        ];
        yield 'ERROR maps to high' => [
            ['extra' => ['severity' => 'ERROR']],
            Finding::SEVERITY_HIGH,
        ];
        yield 'WARNING maps to medium' => [
            ['extra' => ['severity' => 'WARNING']],
            Finding::SEVERITY_MEDIUM,
        ];
        yield 'INFO maps to low' => [
            ['extra' => ['severity' => 'INFO']],
            Finding::SEVERITY_LOW,
        ];
        yield 'missing severity defaults to warning -> medium' => [
            ['extra' => []],
            Finding::SEVERITY_MEDIUM,
        ];
    }

    // -------------------------------------------------------------------------
    // extractOwaspCategory()
    // -------------------------------------------------------------------------

    #[DataProvider('owaspCategoryProvider')]
    public function testExtractOwaspCategory(array $metadata, ?string $expected): void
    {
        $this->assertSame($expected, $this->invokePrivate($this->analyzer, 'extractOwaspCategory', [$metadata]));
    }

    public static function owaspCategoryProvider(): iterable
    {
        yield 'no owasp key' => [[], null];
        yield 'empty owasp list' => [['owasp' => []], null];
        yield 'single 2025 tag' => [['owasp' => ['A05:2025']], 'A05'];
        yield '2021-only tag falls back' => [['owasp' => ['A03:2021']], 'A03'];
        yield '2025 preferred even when listed after 2021' => [
            ['owasp' => ['A01:2021', 'A05:2025']], 'A05',
        ];
        yield 'unknown category code is ignored' => [['owasp' => ['A99:2025']], null];
        yield 'unrecognized tag falls back to next valid one' => [
            ['owasp' => ['A99:2025', 'A02:2021']], 'A02',
        ];
    }

    // -------------------------------------------------------------------------
    // analyze() — seul le garde-fou "pas de sortie" est testable sans dépendre
    // d'un vrai binaire semgrep installé sur la machine.
    // -------------------------------------------------------------------------

    public function testAnalyzeReturnsEmptyArrayWhenProjectPathDoesNotExist(): void
    {
        $missingPath = sys_get_temp_dir() . '/securescan_missing_' . bin2hex(random_bytes(8));

        $findings = $this->analyzer->analyze(new Scan(), $missingPath);

        $this->assertSame([], $findings);
    }

    private function invokePrivate(object $object, string $method, array $args = []): mixed
    {
        return (new \ReflectionMethod($object, $method))->invoke($object, ...$args);
    }
}