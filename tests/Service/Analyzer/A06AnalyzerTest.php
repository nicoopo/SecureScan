<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A06Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A06AnalyzerTest extends AnalyzerTestCase
{
    private A06Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A06Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A06, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'Unvalidated file upload' => ['UploadController.php', '$file->move($directory, $filename);', 'a06.upload.unvalidated_file_upload'],
            'CSRF/security disabled'  => ['security.yaml', 'security: false', 'a06.security.disabled'],
            'Form without validation' => ['FormType.php', '$builder = $this->createForm(ContactType::class);', 'a06.form.missing_validation'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'Service.php' => "<?php\nclass PricingService\n{\n    public function computeTotal(int \$amount): int\n    {\n        return \$amount;\n    }\n}\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}