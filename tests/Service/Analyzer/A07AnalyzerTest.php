<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A07Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A07AnalyzerTest extends AnalyzerTestCase
{
    private A07Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A07Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A07, $finding->getOwaspCategory());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'Hardcoded password' => ['auth.php', '$password = "SuperSecret123";', 'a07.auth.hardcoded_password'],
            'JWT decoded without verification' => ['auth.php', '$decoded = jwt_decode($token);', 'a07.auth.jwt_no_verify'],
        ];
    }

    /**
     * setcookie() sans arguments explicites de flags déclenche les DEUX règles
     * (httponly et secure) car elles partagent la même regex — comportement réel
     * de l'analyseur, verrouillé ici pour éviter une régression silencieuse.
     */
    public function testSetcookieTriggersBothHttponlyAndSecureRules(): void
    {
        $project = $this->createProject([
            'Session.php' => "setcookie('session', \$token, time() + 3600);",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a07.auth.setcookie_no_httponly'));
        $this->assertNotNull($this->findByRuleId($findings, 'a07.auth.setcookie_no_secure'));
    }

    /**
     * Même chose pour session_start() : une seule ligne déclenche deux règles
     * distinctes (config de session absente + pas de régénération d'ID).
     */
    public function testSessionStartTriggersBothConfigAndRegenerateRules(): void
    {
        $project = $this->createProject([
            'Session.php' => 'session_start();',
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a07.auth.session_no_config'));
        $this->assertNotNull($this->findByRuleId($findings, 'a07.auth.no_session_regenerate'));
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'Auth.php' => "<?php\nclass Auth\n{\n    public function login(string \$username): void\n    {\n    }\n}\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}