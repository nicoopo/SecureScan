<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A08Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A08AnalyzerTest extends AnalyzerTestCase
{
    private A08Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A08Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A08, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'unserialize() of superglobal'   => ['handler.php', "\$obj = unserialize(\$_GET['data']);", 'a08.integrity.unserialize_user_input'],
            'Unsafe pickle.loads (Python)'   => ['handler.py', 'data = pickle.loads(raw)', 'a08.integrity.unsafe_deserialize.python'],
            'Unsafe Marshal.load (Ruby)'     => ['handler.rb', 'obj = Marshal.load(raw)', 'a08.integrity.unsafe_deserialize.ruby'],
            'Remote require by URL'          => ['loader.php', "require('https://example.com/lib.php');", 'a08.integrity.require_remote_url'],
        ];
    }

    /**
     * eval($_POST['code']) déclenche à la fois la règle spécifique aux entrées
     * utilisateur ET la règle générique "eval sur variable" (regex qui se
     * chevauchent) — comportement réel verrouillé ici.
     */
    public function testEvalOnUserInputTriggersBothSpecificAndGenericRules(): void
    {
        $project = $this->createProject([
            'handler.php' => "eval(\$_POST['code']);",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a08.integrity.eval_user_input'));
        $this->assertNotNull($this->findByRuleId($findings, 'a08.integrity.eval_variable'));
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'handler.php' => "<?php\n\$data = json_decode(\$request->getContent(), true);\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}