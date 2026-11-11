<?php

namespace App\Tests\Service;

use App\Entity\Project;
use App\Service\ProjectCloner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ProjectClonerTest extends TestCase
{
    private ProjectCloner $cloner;

    /** @var string[] */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        $this->cloner = new ProjectCloner();
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
        $this->tempDirs = [];
    }

    #[DataProvider('markerFileProvider')]
    public function testDetectsLanguageFromMarkerFile(string $markerFile, string $expectedLanguage): void
    {
        $project = $this->createProjectWithFile($markerFile);

        $this->assertSame($expectedLanguage, $this->cloner->detectLanguage($project));
    }

    public static function markerFileProvider(): array
    {
        return [
            'composer.json'    => ['composer.json', Project::LANGUAGE_PHP],
            'package.json'     => ['package.json', Project::LANGUAGE_JAVASCRIPT],
            'requirements.txt' => ['requirements.txt', Project::LANGUAGE_PYTHON],
            'pyproject.toml'   => ['pyproject.toml', Project::LANGUAGE_PYTHON],
            'go.mod'           => ['go.mod', Project::LANGUAGE_GO],
            'Gemfile'          => ['Gemfile', Project::LANGUAGE_RUBY],
            'pom.xml'          => ['pom.xml', Project::LANGUAGE_JAVA],
            'build.gradle'     => ['build.gradle', Project::LANGUAGE_JAVA],
        ];
    }

    public function testComposerJsonTakesPrecedenceOverPackageJson(): void
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;
        file_put_contents($dir . '/composer.json', '{}');
        file_put_contents($dir . '/package.json', '{}');

        $this->assertSame(Project::LANGUAGE_PHP, $this->cloner->detectLanguage($dir));
    }

    public function testReturnsUnknownWhenNoMarkerFilePresent(): void
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;
        file_put_contents($dir . '/README.md', '# empty project');

        $this->assertSame(Project::LANGUAGE_UNKNOWN, $this->cloner->detectLanguage($dir));
    }

    #[DataProvider('unsafeRepositoryUrlProvider')]
    public function testRefusesNonHttpsRepositoryUrls(string $url): void
    {
        $workDir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        $source  = sys_get_temp_dir() . '/securescan_src_' . bin2hex(random_bytes(8));
        mkdir($source, 0777, true);
        exec('git init -q ' . escapeshellarg($source));
        $project = (new Project())->setSource(Project::SOURCE_GIT)->setRepositoryUrl(str_replace('{src}', $source, $url));

        try {
            $this->expectException(\RuntimeException::class);
            (new ProjectCloner($workDir))->clone($project);
        } finally {
            $this->removeDir($workDir);
            $this->removeDir($source);
        }
    }

    public static function unsafeRepositoryUrlProvider(): array
    {
        return [
            'chemin local'       => ['{src}'],
            'file://'            => ['file://{src}'],
            'option git injectée' => ['--upload-pack=touch /tmp/pwned'],
            'ext::'              => ['ext::sh -c touch% /tmp/pwned'],
        ];
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            @chmod($f->getPathname(), 0777);
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
    }

    private function createProjectWithFile(string $markerFile): string
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;
        file_put_contents($dir . '/' . $markerFile, '');

        return $dir;
    }
}