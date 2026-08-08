<?php

namespace App\Tests\Service;

use App\Entity\Project;
use App\Entity\Scan;
use App\Service\GitFixWorkflowService;
use PHPUnit\Framework\TestCase;

/**
 * Tests d'intégration : GitFixWorkflowService pilote un vrai `git` via shell_exec
 * (pas d'abstraction Process injectée), donc on vérifie son comportement contre
 * un dépôt Git réel plutôt que de mocker.
 */
class GitFixWorkflowServiceTest extends TestCase
{
    private GitFixWorkflowService $service;

    /** @var string[] */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        $this->service = new GitFixWorkflowService();
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDirectory($dir);
        }
        $this->tempDirs = [];
    }

    public function testEnsureFixBranchCreatesAndChecksOutANewBranch(): void
    {
        $repo = $this->createGitProject();
        $scan = $this->buildScan($repo);

        $branch = $this->service->ensureFixBranch($scan);

        $this->assertNotNull($branch);
        $this->assertStringStartsWith('fix/securescan-', $branch);
        $this->assertSame($branch, $scan->getFixBranch());
        $this->assertSame($branch, $this->git($repo, 'rev-parse --abbrev-ref HEAD'));
    }

    public function testEnsureFixBranchReusesTheSameBranchAcrossCalls(): void
    {
        $repo = $this->createGitProject();
        $scan = $this->buildScan($repo);

        $first  = $this->service->ensureFixBranch($scan);
        $second = $this->service->ensureFixBranch($scan);

        $this->assertSame($first, $second);
    }

    /**
     * Vérifie explicitement le correctif : si on quitte la branche de fix (ex.
     * un autre process/utilisateur repasse sur main) et qu'on rappelle
     * ensureFixBranch(), le service doit revenir sur la branche existante plutôt
     * que d'échouer à la recréer.
     */
    public function testEnsureFixBranchSwitchesBackToExistingBranchAfterLeavingIt(): void
    {
        $repo = $this->createGitProject();
        $scan = $this->buildScan($repo);

        $branch = $this->service->ensureFixBranch($scan);
        $this->git($repo, 'checkout -q main');
        $this->assertSame('main', $this->git($repo, 'rev-parse --abbrev-ref HEAD'));

        $this->service->ensureFixBranch($scan);

        $this->assertSame($branch, $this->git($repo, 'rev-parse --abbrev-ref HEAD'));
    }

    public function testEnsureFixBranchReturnsNullWhenLocalPathIsMissing(): void
    {
        $scan = $this->buildScan(null);

        $this->assertNull($this->service->ensureFixBranch($scan));
        $this->assertNull($scan->getFixBranch());
    }

    public function testEnsureFixBranchReturnsNullWhenLocalPathDoesNotExist(): void
    {
        $scan = $this->buildScan(sys_get_temp_dir() . '/securescan_does_not_exist_' . bin2hex(random_bytes(6)));

        $this->assertNull($this->service->ensureFixBranch($scan));
    }

    public function testCommitFixCreatesACommitOnTheFixBranch(): void
    {
        $repo = $this->createGitProject();
        $scan = $this->buildScan($repo);
        $this->service->ensureFixBranch($scan);

        file_put_contents($repo . '/app.php', "<?php\n// fixed\n");
        $this->service->commitFix($scan, 'app.php', 'SecureScan: correction proposée');

        $this->assertSame('SecureScan: correction proposée', $this->git($repo, 'log -1 --format=%s'));
        $this->assertSame('', $this->git($repo, 'status --porcelain'));
    }

    public function testCommitFixDoesNothingWhenLocalPathIsMissing(): void
    {
        $scan = $this->buildScan(null);

        // Ne doit pas lever d'exception.
        $this->service->commitFix($scan, 'app.php', 'message');

        $this->assertNull($scan->getProject()?->getLocalPath());
    }

    private function buildScan(?string $localPath): Scan
    {
        $project = new Project();
        if ($localPath !== null) {
            $project->setLocalPath($localPath);
        }

        $scan = new Scan();
        $scan->setProject($project);

        return $scan;
    }

    private function createGitProject(): string
    {
        $dir = sys_get_temp_dir() . '/securescan_git_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;

        $this->git($dir, 'init -q -b main');
        file_put_contents($dir . '/README.md', "# test project\n");
        $this->git($dir, 'add -A');
        $this->git($dir, '-c user.email=test@test.local -c user.name=Test commit -q -m "initial commit"');

        return $dir;
    }

    private function git(string $dir, string $args): string
    {
        $path = escapeshellarg($dir);

        return trim((string) shell_exec("cd {$path} && git {$args} 2>&1"));
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
                @chmod($item->getPathname(), 0666);
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }
}