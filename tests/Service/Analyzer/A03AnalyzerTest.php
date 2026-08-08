<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;
use App\Service\Analyzer\A03Analyzer;

/**
 * Ne couvre que l'analyse statique des manifestes (composer.json, package.json,
 * requirements.txt, go.mod, Gemfile, pom.xml). Les appels shell_exec vers
 * composer/npm/pip-audit/govulncheck/bundler-audit dépendent d'outils externes
 * potentiellement absents de l'environnement de test : on ignore leur sortie en
 * filtrant sur les ruleId des règles statiques plutôt que d'asserter la liste
 * complète des findings.
 */
class A03AnalyzerTest extends AnalyzerTestCase
{
    private A03Analyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new A03Analyzer();
    }

    public function testDetectsUnfixedComposerVersion(): void
    {
        $project = $this->createProject([
            'composer.json' => json_encode(['require' => ['acme/lib' => '*']]),
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $finding = $this->findByRuleId($findings, 'a03.supply.unfixed_version');
        $this->assertNotNull($finding);
        $this->assertSame(Finding::OWASP_A03, $finding->getOwaspCategory());
        $this->assertStringContainsString('acme/lib', $finding->getTitle());
    }

    public function testDetectsKnownVulnerablePackage(): void
    {
        $project = $this->createProject([
            'composer.json' => json_encode(['require' => ['phpmailer/phpmailer' => '5.2.0']]),
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, 'a03.supply.vulnerable_package');

        $this->assertNotNull($finding);
        $this->assertSame(Finding::SEVERITY_CRITICAL, $finding->getSeverity());
    }

    public function testDetectsUnfixedNpmVersion(): void
    {
        $project = $this->createProject([
            'package.json' => json_encode(['dependencies' => ['lodash' => 'latest']]),
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a03.supply.unfixed_version_npm'));
    }

    public function testDetectsUnfixedPipRequirement(): void
    {
        $project = $this->createProject([
            'requirements.txt' => "requests\nflask==2.0.0\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);
        $finding  = $this->findByRuleId($findings, 'a03.supply.unfixed_version_pip');

        $this->assertNotNull($finding);
        $this->assertSame(1, $finding->getLine());
    }

    public function testDetectsMissingGoSum(): void
    {
        $project = $this->createProject([
            'go.mod' => "module example.com/app\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a03.supply.go_missing_sum'));
    }

    public function testDetectsMissingGemfileLockAndUnfixedGem(): void
    {
        $project = $this->createProject([
            'Gemfile' => "source 'https://rubygems.org'\ngem 'rails'\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a03.supply.missing_gemfile_lock'));
        $this->assertNotNull($this->findByRuleId($findings, 'a03.supply.unfixed_version_gem'));
    }

    public function testDetectsUnfixedMavenVersion(): void
    {
        $project = $this->createProject([
            'pom.xml' => "<project>\n  <version>LATEST</version>\n</project>\n",
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $this->assertNotNull($this->findByRuleId($findings, 'a03.supply.unfixed_version_maven'));
    }

    public function testFixedVersionsProduceNoStaticFindings(): void
    {
        $project = $this->createProject([
            'composer.json' => json_encode(['require' => ['symfony/console' => '7.1.3']]),
        ]);

        $findings = $this->analyzer->analyze(new Scan(), $project);

        $staticRuleIds = ['a03.supply.unfixed_version', 'a03.supply.vulnerable_package'];
        $triggeredStaticRuleIds = array_intersect(
            array_map(static fn (Finding $f) => $f->getRuleId(), $findings),
            $staticRuleIds
        );

        $this->assertSame([], array_values($triggeredStaticRuleIds));
    }
}