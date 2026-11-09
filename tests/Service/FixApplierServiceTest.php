<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Fix;
use App\Entity\Project;
use App\Entity\Scan;
use App\Service\FixApplierService;
use PHPUnit\Framework\TestCase;

class FixApplierServiceTest extends TestCase
{
    private FixApplierService $service;

    /** @var string[] */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        $this->service = new FixApplierService();
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDirectory($dir);
        }
        $this->tempDirs = [];
    }

    public function testInsertsAnnotationAboveTargetLineForPhpFile(): void
    {
        $project = $this->createProject([
            'Controller.php' => "<?php\n\$result = \$db->query(\"SELECT * FROM users WHERE id = \" . \$id);\n",
        ]);

        $fix = $this->buildFix($project, 'Controller.php', lineStart: 2, originalCode: null, proposedCode: '$stmt = $pdo->prepare(...);', explanation: 'Utiliser des requêtes préparées.');

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $this->assertStringContainsString('Controller.php', $result['message']);

        $content = file_get_contents($project . '/Controller.php');
        $this->assertStringContainsString('// [SecureScan] Correction proposée (a05.injection.sql_raw)', $content);
        $this->assertStringContainsString('// Utiliser des requêtes préparées.', $content);
        $this->assertStringContainsString('// $stmt = $pdo->prepare(...);', $content);
        // Le code original n'est ni modifié ni supprimé.
        $this->assertStringContainsString('$result = $db->query("SELECT * FROM users WHERE id = " . $id);', $content);
    }

    public function testUsesHashCommentStyleForPythonFiles(): void
    {
        $project = $this->createProject(['app.py' => "import hashlib\nhashlib.md5(data)\n"]);
        $fix     = $this->buildFix($project, 'app.py', lineStart: 2, originalCode: null, proposedCode: 'hashlib.sha256(data)');

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $content = file_get_contents($project . '/app.py');
        $this->assertStringContainsString('# [SecureScan] Correction proposée', $content);
        $this->assertStringContainsString('# hashlib.sha256(data)', $content);
    }

    public function testUsesHashCommentStyleForDockerfileBasename(): void
    {
        $project = $this->createProject(['Dockerfile' => "FROM php:8.4\nUSER root\n"]);
        $fix     = $this->buildFix($project, 'Dockerfile', lineStart: 2, originalCode: null, proposedCode: 'USER www-data');

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $content = file_get_contents($project . '/Dockerfile');
        $this->assertStringContainsString('# [SecureScan] Correction proposée', $content);
    }

    public function testUsesBlockCommentStyleForXmlFiles(): void
    {
        $project = $this->createProject(['pom.xml' => "<project>\n  <version>LATEST</version>\n</project>\n"]);
        $fix     = $this->buildFix($project, 'pom.xml', lineStart: 2, originalCode: null, proposedCode: '<version>1.2.3</version>');

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $content = file_get_contents($project . '/pom.xml');
        $this->assertStringContainsString('<!-- [SecureScan] Correction proposée (a05.injection.sql_raw) -->', $content);
        $this->assertStringContainsString('<!-- <version>1.2.3</version> -->', $content);
    }

    public function testInsertsKeyAnnotationForJsonFiles(): void
    {
        $project = $this->createProject([
            'composer.json' => "{\n    \"require\": {\n        \"acme/lib\": \"*\"\n    }\n}\n",
        ]);
        $fix = $this->buildFix($project, 'composer.json', lineStart: 3, originalCode: null, proposedCode: '"acme/lib": "1.2.3"', explanation: 'Fixer une version précise.');

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);

        $content = file_get_contents($project . '/composer.json');
        $decoded = json_decode($content, true);

        $this->assertNotNull($decoded, 'The annotated file must remain valid JSON.');
        $annotationKey = array_filter(array_keys($decoded), static fn ($k) => str_starts_with($k, '// [SecureScan]'));
        $this->assertNotEmpty($annotationKey);
        $this->assertStringContainsString('Fixer une version précise.', $decoded[array_values($annotationKey)[0]]);
    }

    public function testJsonAnnotationFailsWhenFirstLineHasNoOpeningBrace(): void
    {
        $project = $this->createProject(['data.json' => "[]\n"]);
        $fix      = $this->buildFix($project, 'data.json', lineStart: 1, originalCode: null, proposedCode: 'x');

        $result = $this->service->apply($fix);

        $this->assertFalse($result['applied']);
        $this->assertStringContainsString('Structure JSON inattendue', $result['message']);
    }

    public function testReturnsFailureForUnsupportedExtension(): void
    {
        $project = $this->createProject(['logo.png' => 'binary-content']);
        $fix     = $this->buildFix($project, 'logo.png', lineStart: 1, originalCode: null, proposedCode: 'x');

        $result = $this->service->apply($fix);

        $this->assertFalse($result['applied']);
        $this->assertStringContainsString('non pris en charge', $result['message']);
    }

    public function testReturnsFailureWhenLocalPathMissing(): void
    {
        $fix = $this->buildFix(null, 'Controller.php', lineStart: 1, originalCode: null, proposedCode: 'x');

        $result = $this->service->apply($fix);

        $this->assertFalse($result['applied']);
        $this->assertStringContainsString('Chemin du fichier introuvable', $result['message']);
    }

    public function testReturnsFailureWhenFileDoesNotExist(): void
    {
        $project = $this->createProject([]);
        $fix     = $this->buildFix($project, 'Missing.php', lineStart: 1, originalCode: null, proposedCode: 'x');

        $result = $this->service->apply($fix);

        $this->assertFalse($result['applied']);
        $this->assertStringContainsString('en dehors du projet', $result['message']);
    }

    public function testBlocksPathTraversalOutsideProjectRoot(): void
    {
        $root = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($root . '/project', 0777, true);
        $this->tempDirs[] = $root;
        file_put_contents($root . '/outside.php', "<?php\necho 'leaked';\n");

        $fix = $this->buildFix($root . '/project', '../outside.php', lineStart: 1, originalCode: null, proposedCode: 'x');

        $result = $this->service->apply($fix);

        $this->assertFalse($result['applied']);
        $this->assertStringContainsString('en dehors du projet', $result['message']);
        $this->assertStringNotContainsString('SecureScan', file_get_contents($root . '/outside.php'));
    }

    public function testLocatesInsertionByMatchingOriginalCodeWithinWindow(): void
    {
        // lineStart pointe sur une ligne décalée (ex: le fichier a bougé depuis le scan),
        // mais le code original est retrouvé à 2 lignes de distance et l'annotation
        // est insérée au bon endroit plutôt qu'à l'endroit désormais incorrect.
        $project = $this->createProject([
            'Controller.php' => "<?php\n// commentaire ajouté depuis le scan\n\$result = \$db->query(\"SELECT * FROM users WHERE id = \" . \$id);\necho 'après';\n",
        ]);

        $fix = $this->buildFix(
            $project,
            'Controller.php',
            lineStart: 2,
            originalCode: '$result = $db->query("SELECT * FROM users WHERE id = " . $id);',
            proposedCode: 'use prepared statements'
        );

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $lines = file($project . '/Controller.php', FILE_IGNORE_NEW_LINES);
        // L'annotation est insérée à l'index où le code original a été retrouvé (2),
        // pas à lineStart - 1 (1), qui pointait sur la mauvaise ligne.
        $this->assertStringContainsString('SecureScan', $lines[2]);
        $this->assertStringContainsString('$result = $db->query', implode("\n", array_slice($lines, 3)));
    }

    public function testFallsBackToLineStartWhenOriginalCodeNotFoundNearby(): void
    {
        $project = $this->createProject([
            'Controller.php' => "<?php\n\$a = 1;\n\$b = 2;\n\$c = 3;\n",
        ]);

        $fix = $this->buildFix(
            $project,
            'Controller.php',
            lineStart: 3,
            originalCode: 'this code does not exist anywhere in the file',
            proposedCode: 'x'
        );

        $result = $this->service->apply($fix);

        $this->assertTrue($result['applied']);
        $lines = file($project . '/Controller.php', FILE_IGNORE_NEW_LINES);
        // default = max(0, lineStart - 1) = 2
        $this->assertStringContainsString('SecureScan', $lines[2]);
    }

    private function createProject(array $files): string
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;

        foreach ($files as $relativePath => $content) {
            $path   = $dir . '/' . ltrim($relativePath, '/\\');
            $parent = dirname($path);
            if (!is_dir($parent)) {
                mkdir($parent, 0777, true);
            }
            file_put_contents($path, $content);
        }

        return $dir;
    }

    private function buildFix(
        ?string $localPath,
        ?string $relativeFilePath,
        ?int $lineStart,
        ?string $originalCode,
        string $proposedCode,
        ?string $explanation = null,
        string $ruleId = 'a05.injection.sql_raw'
    ): Fix {
        $project = new Project();
        if ($localPath !== null) {
            $project->setLocalPath($localPath);
        }

        $scan = new Scan();
        $scan->setProject($project);

        $finding = new Finding();
        $finding
            ->setScan($scan)
            ->setTool('securescan')
            ->setSeverity(Finding::SEVERITY_HIGH)
            ->setOwaspCategory(Finding::OWASP_A05)
            ->setRuleId($ruleId)
            ->setTitle('Test finding');

        $fix = new Fix();
        $fix
            ->setFinding($finding)
            ->setFilePath($relativeFilePath)
            ->setLineStart($lineStart)
            ->setOriginalCode($originalCode)
            ->setProposedCode($proposedCode)
            ->setExplanation($explanation);

        return $fix;
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (new \FilesystemIterator($dir) as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir()) {
                $this->removeDirectory($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }
}