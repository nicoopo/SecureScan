<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A010Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A010AnalyzerTest extends AnalyzerTestCase
{
    private A010Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A010Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A10, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'Exception message echoed'   => ['Controller.php', 'echo $e->getMessage();', 'a10.exception.expose_message'],
            'Stack trace printed (Java)' => ['Handler.java', 'e.printStackTrace();', 'a10.exception.expose_trace.java'],
            'die() with dynamic message' => ['api.php', 'die($error);', 'a10.exception.die_with_message'],
            'var_dump on exception'      => ['debug.php', 'var_dump($e);', 'a10.exception.var_dump_exception'],
        ];
    }

    /**
     * `catch (Exception $e) {}` déclenche à la fois "empty_catch" et
     * "generic_exception" (le type Exception générique est capturé par les
     * deux regex) — comportement réel verrouillé ici.
     */
    public function testGenericEmptyCatchTriggersTwoRules(): void
    {
        $project = $this->createProject([
            'Controller.php' => 'catch (Exception $e) {}',
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a10.exception.empty_catch'));
        $this->assertNotNull($this->findByRuleId($findings, 'a10.exception.generic_exception'));
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'Controller.php' => "<?php\ntry {\n    \$this->run();\n} catch (\\InvalidArgumentException \$e) {\n    \$this->logger->error(\$e->getMessage());\n    throw \$e;\n}\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}