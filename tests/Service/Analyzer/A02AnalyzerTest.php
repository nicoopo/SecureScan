<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A02Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A02AnalyzerTest extends AnalyzerTestCase
{
    private A02Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A02Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A02, $finding->getOwaspCategory());
        $this->assertSame(1, $finding->getLine());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'APP_DEBUG=true'            => ['.env', 'APP_DEBUG=true', 'a02.debug.app_debug_true'],
            'phpinfo()'                 => ['debug.php', 'phpinfo();', 'a02.debug.phpinfo'],
            'display_errors On'         => ['config.ini', 'display_errors = On', 'a02.debug.display_errors_on'],
            'error_reporting(E_ALL)'    => ['debug.php', 'error_reporting(E_ALL);', 'a02.debug.error_reporting_all'],
            'default APP_SECRET'        => ['.env', 'APP_SECRET=ThisTokenIsNotSoSecretChangeIt', 'a02.config.default_app_secret'],
            'weak database password'    => ['.env', 'DATABASE_URL=mysql://user:password@127.0.0.1:3306/db', 'a02.config.weak_database_password'],
            'expose_php On'             => ['php.ini', 'expose_php = On', 'a02.config.expose_php_version'],
            'hardcoded credentials'     => ['config.php', '$api_key = "abc123456";', 'a02.config.hardcoded_credentials'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            '.env'         => "APP_DEBUG=false\nAPP_SECRET=%env(resolve:APP_SECRET)%\n",
            'config.php'   => "<?php\n\$apiKey = getenv('API_KEY');\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}