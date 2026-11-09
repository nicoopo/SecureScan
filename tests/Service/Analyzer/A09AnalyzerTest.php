<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A09Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A09AnalyzerTest extends AnalyzerTestCase
{
    private A09Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A09Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A09, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'Empty catch block'         => ['Handler.php', '} catch (Exception $e) {}', 'a09.logging.empty_catch'],
            'error_reporting disabled'  => ['bootstrap.php', 'error_reporting(0);', 'a09.logging.error_reporting_disabled'],
            'Error suppression operator' => ['io.php', "@file_get_contents(\$url);", 'a09.logging.at_operator_suppress'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'Handler.php' => "<?php\ntry {\n    \$this->run();\n} catch (\\Throwable \$e) {\n    \$this->logger->error(\$e->getMessage());\n}\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}