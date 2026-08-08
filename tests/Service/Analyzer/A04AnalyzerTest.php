<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A04Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A04AnalyzerTest extends AnalyzerTestCase
{
    private A04Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A04Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A04, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'MD5 (PHP)'               => ['hash.php', '$hash = md5($password);', 'a04.crypto.md5'],
            'MD5 (Python)'            => ['hash.py', 'digest = hashlib.md5(data)', 'a04.crypto.md5.python'],
            'SHA1 (PHP)'              => ['hash.php', '$hash = sha1($data);', 'a04.crypto.sha1'],
            'Plaintext password'      => ['config.php', '$password = "SuperSecret123";', 'a04.crypto.plaintext_password'],
            'Base64-encoded password' => ['auth.php', '$encoded = base64_encode($password);', 'a04.crypto.base64_password'],
            'Weak RNG (PHP)'          => ['token.php', '$token = rand();', 'a04.crypto.weak_random'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'auth.php' => "<?php\n\$hashed = password_hash(\$input, PASSWORD_BCRYPT);\n\$token = random_bytes(16);\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}