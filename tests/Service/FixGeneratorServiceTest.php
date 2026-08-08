<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Fix;
use App\Service\FixGeneratorService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class FixGeneratorServiceTest extends TestCase
{
    private FixGeneratorService $service;

    protected function setUp(): void
    {
        $this->service = new FixGeneratorService();
    }

    public function testGeneratesPendingTemplateFixWiredToTheFinding(): void
    {
        $finding = $this->buildFinding(
            ruleId: 'a05.injection.sql_raw',
            filePath: 'db.php',
            line: 12,
            codeSnippet: '$db->query("SELECT * FROM users WHERE id = " . $id);',
            description: 'Utiliser des requêtes préparées.'
        );

        $fix = $this->service->generate($finding);

        $this->assertSame(Fix::TYPE_TEMPLATE, $fix->getType());
        $this->assertSame(Fix::STATUS_PENDING, $fix->getStatus());
        $this->assertSame('$db->query("SELECT * FROM users WHERE id = " . $id);', $fix->getOriginalCode());
        $this->assertSame('Utiliser des requêtes préparées.', $fix->getExplanation());
        $this->assertSame('db.php', $fix->getFilePath());
        $this->assertSame(12, $fix->getLineStart());
        $this->assertSame(12, $fix->getLineEnd());
        $this->assertStringContainsString('requête préparée', $fix->getProposedCode());

        // generate() doit relier le Fix au Finding dans les deux sens.
        $this->assertSame($finding, $fix->getFinding());
        $this->assertTrue($finding->getFixes()->contains($fix));
    }

    public function testExplanationFallsBackToTitleWhenDescriptionIsMissing(): void
    {
        $finding = $this->buildFinding(ruleId: 'a04.crypto.md5', description: null, title: 'Algorithme MD5 utilisé');

        $fix = $this->service->generate($finding);

        $this->assertSame('Algorithme MD5 utilisé', $fix->getExplanation());
    }

    #[DataProvider('templateProvider')]
    public function testResolvesExpectedTemplateByRuleId(string $ruleId, string $expectedMarker): void
    {
        $finding = $this->buildFinding(ruleId: $ruleId);

        $fix = $this->service->generate($finding);

        $this->assertStringContainsString($expectedMarker, $fix->getProposedCode());
    }

    public static function templateProvider(): array
    {
        return [
            'SQL injection (A05)'        => ['a05.injection.sql_raw', 'requête préparée'],
            'XSS via echo (A05)'         => ['a05.injection.xss_echo', 'htmlspecialchars'],
            'MD5 (A04)'                  => ['a04.crypto.md5', 'password_hash'],
            'Plaintext password (A04)'   => ['a04.crypto.plaintext_password', 'password_verify'],
            'CORS wildcard (A01)'        => ['a01.cors.wildcard_header', 'Access-Control-Allow-Origin'],
            'Debug mode (A02)'           => ['a02.debug.app_debug_true', 'APP_DEBUG=0'],
            'JWT no verify (A07)'        => ['a07.auth.jwt_no_verify', 'JWT::decode'],
            'Cookie flags (A07)'         => ['a07.auth.setcookie_no_httponly', 'samesite'],
            'Unvalidated upload (A06)'   => ['a06.upload.unvalidated_file_upload', 'guessExtension'],
            'Unsafe unserialize (A08)'   => ['a08.integrity.unserialize_user_input', 'json_decode'],
            'Empty catch (A09)'          => ['a09.logging.empty_catch', "logger->error('Erreur"],
            'Exposed exception (A10)'    => ['a10.exception.expose_message', 'Une erreur est survenue'],
            'Vulnerable package (A03)'   => ['a03.supply.vulnerable_package', 'composer require'],
        ];
    }

    /**
     * L'ordre des clés dans TEMPLATES fait foi : `privilege` (A01) est déclaré avant
     * `hardcoded_admin_bypass` (A02), donc un ruleId contenant les deux sous-chaînes
     * reçoit le template `privilege`, jamais celui de `hardcoded_admin_bypass`.
     * Comportement réel, verrouillé ici pour éviter une régression silencieuse si
     * l'ordre du tableau change.
     */
    public function testFirstMatchingKeyInDeclarationOrderWins(): void
    {
        $finding = $this->buildFinding(ruleId: 'a01.privilege.hardcoded_admin_bypass');

        $fix = $this->service->generate($finding);

        $this->assertStringContainsString('vérification de rôle/permission', $fix->getProposedCode());
        $this->assertStringNotContainsString('codé en dur', $fix->getProposedCode());
    }

    public function testFallsBackToGenericOwaspAdviceWhenRuleIdMatchesNoTemplate(): void
    {
        $finding = $this->buildFinding(
            ruleId: 'zzz.totally.unknown.rule',
            description: 'Description du finding.'
        );

        $fix = $this->service->generate($finding);

        $this->assertStringContainsString('Corriger selon la recommandation OWASP', $fix->getProposedCode());
        $this->assertStringContainsString(Finding::OWASP_A01, $fix->getProposedCode());
        $this->assertStringContainsString('Description du finding.', $fix->getProposedCode());
    }

    public function testFallsBackToGenericOwaspAdviceWhenRuleIdIsNull(): void
    {
        $finding = $this->buildFinding(ruleId: null);

        $fix = $this->service->generate($finding);

        $this->assertStringContainsString('Corriger selon la recommandation OWASP', $fix->getProposedCode());
    }

    private function buildFinding(
        ?string $ruleId,
        string $filePath = 'Controller.php',
        int $line = 1,
        ?string $codeSnippet = 'code();',
        ?string $description = 'Description par défaut.',
        string $title = 'Finding de test',
        string $owaspCategory = Finding::OWASP_A01
    ): Finding {
        $finding = new Finding();
        $finding
            ->setTool('securescan')
            ->setSeverity(Finding::SEVERITY_HIGH)
            ->setOwaspCategory($owaspCategory)
            ->setRuleId($ruleId)
            ->setTitle($title)
            ->setDescription($description)
            ->setFilePath($filePath)
            ->setLine($line)
            ->setCodeSnippet($codeSnippet);

        return $finding;
    }
}