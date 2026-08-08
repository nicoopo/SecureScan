<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A01Analyzer;
use PHPUnit\Framework\Attributes\DataProvider;

class A01AnalyzerTest extends AnalyzerTestCase
{
    private A01Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A01Analyzer();
    }

    #[DataProvider('vulnerableLineProvider')]
    public function testDetectsVulnerablePattern(string $filename, string $line, string $expectedRuleId): void
    {
        $project = $this->createProject([$filename => $line]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, $expectedRuleId);

        $this->assertNotNull($finding, "Expected rule {$expectedRuleId} to be triggered by: {$line}");
        $this->assertSame(Finding::OWASP_A01, $finding->getOwaspCategory());
        $this->assertSame('securescan', $finding->getTool());
        $this->assertSame(1, $finding->getLine());
        $this->assertSame($filename, $finding->getFilePath());
    }

    public static function vulnerableLineProvider(): array
    {
        return [
            'CORS wildcard header'          => ['config.php', "header('Access-Control-Allow-Origin: *');", 'a01.cors.wildcard_header'],
            'CORS allowedOrigins wildcard'   => ['cors.yaml', "allowedOrigins: ['*']", 'a01.cors.allow_all_origins_config'],
            'IDOR raw superglobal'          => ['Controller.php', '$user = $repository->find($_GET["id"]);', 'a01.idor.raw_superglobal_in_query'],
            'IDOR request param'            => ['Controller.php', '$user = $repository->find($request->get("id"));', 'a01.idor.find_request_param'],
            'Commented access check'        => ['Controller.php', '// $this->denyAccessUnlessGranted("ROLE_ADMIN");', 'a01.privilege.commented_access_check'],
            'Hardcoded admin bypass'        => ['Controller.php', 'if (true) { // isAdmin bypass', 'a01.privilege.hardcoded_admin_bypass'],
        ];
    }

    public function testCleanCodeProducesNoFindings(): void
    {
        $project = $this->createProject([
            'Controller.php' => "<?php\n\$user = \$repository->find(\$id);\nif (\$this->isGranted('ROLE_ADMIN')) {\n    // ok\n}\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }

    public function testIgnoresVendorAndNodeModulesDirectories(): void
    {
        $project = $this->createProject([
            'vendor/lib/evil.php'      => "header('Access-Control-Allow-Origin: *');",
            'node_modules/pkg/evil.js' => "header('Access-Control-Allow-Origin: *');",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertSame([], $findings);
    }
}