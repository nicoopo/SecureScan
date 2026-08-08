<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A05Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A05AnalyzerTest extends AnalyzerTestCase
{
    private A05Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A05Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A05, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'SQL injection (raw query)'    => ['db.php', '$result = $db->query("SELECT * FROM users WHERE id = " . $id);', 'a05.injection.sql_raw'],
            'XSS via echo'                 => ['view.php', "echo \$_GET['name'];", 'a05.injection.xss_echo'],
            'Command injection'            => ['run.php', 'exec($cmd);', 'a05.injection.command_injection'],
            'eval() with variable'         => ['run.php', 'eval($code);', 'a05.injection.eval'],
            'XSS via innerHTML'            => ['app.js', 'element.innerHTML = userInput;', 'a05.injection.xss_innerhtml'],
            'SQL injection (Python f-string)' => ['app.py', 'cursor.execute(f"SELECT * FROM users WHERE id={id}")', 'a05.injection.sql_string_interp.python'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'db.php' => "<?php\n\$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = ?');\n\$stmt->execute([\$id]);\necho htmlspecialchars(\$_GET['name']);\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}