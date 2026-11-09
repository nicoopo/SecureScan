<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Entity\Fix;
use App\Entity\Project;
use App\Entity\Scan;
use App\Service\GitHubPushService;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * push() mélange de vrais appels shell (`git push` vers github.com) et des appels
 * à l'API REST GitHub. Le `git push` réel ne peut pas être exercé en test unitaire
 * sans réseau ni vraies infos d'identification : on le fait échouer volontairement
 * et de façon déterministe (aucun accès réseau) en pointant `localPath` vers un
 * répertoire qui n'est PAS un dépôt Git — `git push` échoue alors instantanément
 * côté client ("fatal: not a git repository"), sans jamais toucher le réseau.
 * Ça couvre tout le chemin public push() jusqu'à l'appel de pushBranch(), avec le
 * cas d'échec de ce dernier.
 *
 * La logique après un push Git réussi (ouverture de PR, fallback sur une PR
 * existante) n'est donc jamais atteignable via push() dans ces conditions : elle
 * est testée directement via Reflection sur les méthodes privées concernées,
 * qui ne font que des appels HTTP (entièrement mockables).
 */
#[AllowMockObjectsWithoutExpectations]
class GitHubPushServiceTest extends TestCase
{
    private LoggerInterface&MockObject $logger;

    /** @var string[] */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerInterface::class);
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            @rmdir($dir);
        }
        $this->tempDirs = [];
    }

    // -------------------------------------------------------------------------
    // push() — garde-fous (aucun appel HTTP attendu)
    // -------------------------------------------------------------------------

    public function testReturnsFailureWhenNoFixBranchIsSet(): void
    {
        $calls = 0;
        $scan  = $this->buildScan(fixBranch: null, localPath: $this->createTempDir());

        $result = $this->buildService($this->trackingClient($calls))->push($scan);

        $this->assertFalse($result['success']);
        $this->assertSame(0, $calls);
    }

    public function testReturnsFailureWhenLocalPathIsMissing(): void
    {
        $calls = 0;
        $scan  = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: null);

        $result = $this->buildService($this->trackingClient($calls))->push($scan);

        $this->assertFalse($result['success']);
        $this->assertSame(0, $calls);
    }

    public function testReturnsFailureWhenLocalPathDoesNotExistOnDisk(): void
    {
        $calls = 0;
        $scan  = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: sys_get_temp_dir() . '/securescan_missing_' . bin2hex(random_bytes(6)));

        $result = $this->buildService($this->trackingClient($calls))->push($scan);

        $this->assertFalse($result['success']);
        $this->assertSame(0, $calls);
    }

    public function testReturnsFailureWhenGithubTokenIsEmpty(): void
    {
        $calls = 0;
        $scan  = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir());

        $result = $this->buildService($this->trackingClient($calls), token: '')->push($scan);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('GITHUB_TOKEN', $result['message']);
        $this->assertSame(0, $calls);
    }

    public function testReturnsFailureWhenRepositoryUrlCannotBeParsed(): void
    {
        $calls = 0;
        $scan  = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir(), repositoryUrl: 'https://gitlab.com/acme/demo.git');

        $result = $this->buildService($this->trackingClient($calls))->push($scan);

        $this->assertFalse($result['success']);
        $this->assertSame(0, $calls);
    }

    // -------------------------------------------------------------------------
    // push() — via l'API GitHub réelle (mockée), puis échec déterministe du git push
    // -------------------------------------------------------------------------

    public function testReturnsFailureWhenRepoInfoCannotBeFetched(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('{}', ['http_code' => 404]));
        $scan   = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir());

        $result = $this->buildService($client)->push($scan);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString("Impossible d'accéder au dépôt", $result['message']);
    }

    public function testReturnsFailureWhenCannotPushAndForkCreationFails(): void
    {
        $client = new MockHttpClient([
            fn () => new MockResponse(json_encode(['default_branch' => 'main', 'permissions' => ['push' => false]]), ['http_code' => 200]),
            fn () => new MockResponse(json_encode(['message' => 'Forbidden']), ['http_code' => 403]),
        ]);
        $scan = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir());

        $result = $this->buildService($client)->push($scan);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('impossible de le forker', $result['message']);
    }

    public function testReturnsGitPushFailureMessageWhenLocalPathIsNotAGitRepository(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['default_branch' => 'main', 'permissions' => ['push' => true]]),
            ['http_code' => 200]
        ));
        $scan = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir());

        $result = $this->buildService($client)->push($scan);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Échec du push vers GitHub', $result['message']);
        $this->assertNull($result['prUrl']);
    }

    public function testFallsBackToForkThenStillFailsOnGitPush(): void
    {
        $client = new MockHttpClient([
            // getRepoInfo : pas de droit d'écriture
            fn () => new MockResponse(json_encode(['default_branch' => 'main', 'permissions' => ['push' => false]]), ['http_code' => 200]),
            // ensureFork : création réussie
            fn () => new MockResponse(json_encode(['owner' => ['login' => 'my-account'], 'name' => 'demo']), ['http_code' => 202]),
            // waitUntilReady : le fork est immédiatement accessible
            fn () => new MockResponse('{}', ['http_code' => 200]),
        ]);
        $scan = $this->buildScan(fixBranch: 'fix/securescan-1', localPath: $this->createTempDir());

        $result = $this->buildService($client)->push($scan);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('Échec du push vers GitHub', $result['message']);
    }

    // -------------------------------------------------------------------------
    // parseOwnerRepo() — logique pure, testée via Reflection
    // -------------------------------------------------------------------------

    #[DataProvider('ownerRepoUrlProvider')]
    public function testParseOwnerRepoExtractsOwnerAndRepo(?string $url, array $expected): void
    {
        $service = $this->buildService(new MockHttpClient());

        $this->assertSame($expected, $this->invokePrivate($service, 'parseOwnerRepo', [$url]));
    }

    public static function ownerRepoUrlProvider(): array
    {
        return [
            'HTTPS avec .git'         => ['https://github.com/acme/demo.git', ['acme', 'demo']],
            'HTTPS sans .git'         => ['https://github.com/acme/demo', ['acme', 'demo']],
            'SSH'                     => ['git@github.com:acme/demo.git', ['acme', 'demo']],
            'HTTPS avec slash final'  => ['https://github.com/acme/demo/', ['acme', 'demo']],
            'Hôte non-GitHub'         => ['https://gitlab.com/acme/demo.git', [null, null]],
            'URL nulle'               => [null, [null, null]],
            'Chaîne vide'             => ['', [null, null]],
        ];
    }

    // -------------------------------------------------------------------------
    // getRepoInfo() — via Reflection
    // -------------------------------------------------------------------------

    public function testGetRepoInfoReturnsDefaultBranchAndPushPermission(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['default_branch' => 'develop', 'permissions' => ['push' => true]]),
            ['http_code' => 200]
        ));

        $result = $this->invokePrivate($this->buildService($client), 'getRepoInfo', ['acme', 'demo']);

        $this->assertSame(['defaultBranch' => 'develop', 'canPush' => true], $result);
    }

    public function testGetRepoInfoDefaultsWhenFieldsAreMissing(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('{}', ['http_code' => 200]));

        $result = $this->invokePrivate($this->buildService($client), 'getRepoInfo', ['acme', 'demo']);

        $this->assertSame(['defaultBranch' => 'main', 'canPush' => false], $result);
    }

    public function testGetRepoInfoReturnsNullOnErrorStatus(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('{}', ['http_code' => 404]));

        $this->assertNull($this->invokePrivate($this->buildService($client), 'getRepoInfo', ['acme', 'demo']));
    }

    public function testGetRepoInfoReturnsNullOnTransportFailure(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('', ['error' => 'Connection refused']));

        $this->assertNull($this->invokePrivate($this->buildService($client), 'getRepoInfo', ['acme', 'demo']));
    }

    // -------------------------------------------------------------------------
    // ensureFork() — via Reflection
    // -------------------------------------------------------------------------

    public function testEnsureForkReturnsForkOwnerAndRepoOnSuccess(): void
    {
        $client = new MockHttpClient([
            fn () => new MockResponse(json_encode(['owner' => ['login' => 'my-account'], 'name' => 'demo']), ['http_code' => 202]),
            fn () => new MockResponse('{}', ['http_code' => 200]), // waitUntilReady : prêt immédiatement
        ]);

        $result = $this->invokePrivate($this->buildService($client), 'ensureFork', ['acme', 'demo']);

        $this->assertSame(['my-account', 'demo'], $result);
    }

    public function testEnsureForkReturnsNullAndLogsOnErrorStatus(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(json_encode(['message' => 'Forbidden']), ['http_code' => 403]));

        $this->logger->expects($this->once())
            ->method('error')
            ->with($this->anything(), $this->callback(static fn (array $ctx) => $ctx['message'] === 'Forbidden'));

        $this->assertNull($this->invokePrivate($this->buildService($client), 'ensureFork', ['acme', 'demo']));
    }

    public function testEnsureForkReturnsNullAndLogsOnTransportFailure(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('', ['error' => 'Connection refused']));

        $this->logger->expects($this->once())->method('error');

        $this->assertNull($this->invokePrivate($this->buildService($client), 'ensureFork', ['acme', 'demo']));
    }

    public function testEnsureForkReturnsNullWhenResponseIsMissingOwnerOrName(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(json_encode(['owner' => null, 'name' => null]), ['http_code' => 202]));

        $this->assertNull($this->invokePrivate($this->buildService($client), 'ensureFork', ['acme', 'demo']));
    }

    // -------------------------------------------------------------------------
    // openPullRequest() / findExistingPullRequest() / buildPullRequestBody() — via Reflection
    // -------------------------------------------------------------------------

    public function testOpenPullRequestReturnsHtmlUrlOnSuccessWithExpectedPayload(): void
    {
        $captured = [];
        $client = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured = ['method' => $method, 'url' => $url, 'body' => json_decode($options['body'] ?? 'null', true)];

            return new MockResponse(json_encode(['html_url' => 'https://github.com/acme/demo/pull/42']), ['http_code' => 201]);
        });
        $scan = $this->buildScanWithAcceptedFix();

        $result = $this->invokePrivate(
            $this->buildService($client),
            'openPullRequest',
            ['acme', 'demo', 'my-account', 'fix/securescan-1', 'main', $scan]
        );

        $this->assertSame('https://github.com/acme/demo/pull/42', $result);
        $this->assertSame('https://api.github.com/repos/acme/demo/pulls', $captured['url']);
        $this->assertSame('my-account:fix/securescan-1', $captured['body']['head']);
        $this->assertSame('main', $captured['body']['base']);
        $this->assertStringContainsString('db.php', $captured['body']['body']);
    }

    public function testOpenPullRequestFallsBackToExistingPullRequestOn422(): void
    {
        $client = new MockHttpClient([
            fn () => new MockResponse(json_encode(['message' => 'A pull request already exists']), ['http_code' => 422]),
            fn () => new MockResponse(json_encode([['html_url' => 'https://github.com/acme/demo/pull/7']]), ['http_code' => 200]),
        ]);
        $scan = $this->buildScanWithAcceptedFix();

        $result = $this->invokePrivate(
            $this->buildService($client),
            'openPullRequest',
            ['acme', 'demo', 'my-account', 'fix/securescan-1', 'main', $scan]
        );

        $this->assertSame('https://github.com/acme/demo/pull/7', $result);
    }

    public function testOpenPullRequestReturnsNullAndLogsWhenNoExistingPullRequestIsFound(): void
    {
        $client = new MockHttpClient([
            fn () => new MockResponse(json_encode(['message' => 'Validation failed']), ['http_code' => 422]),
            fn () => new MockResponse('[]', ['http_code' => 200]),
        ]);
        $scan = $this->buildScanWithAcceptedFix();

        $this->logger->expects($this->once())->method('error');

        $result = $this->invokePrivate(
            $this->buildService($client),
            'openPullRequest',
            ['acme', 'demo', 'my-account', 'fix/securescan-1', 'main', $scan]
        );

        $this->assertNull($result);
    }

    public function testOpenPullRequestReturnsNullAndLogsOnTransportFailure(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('', ['error' => 'Connection refused']));
        $scan   = $this->buildScanWithAcceptedFix();

        $this->logger->expects($this->once())->method('error');

        $result = $this->invokePrivate(
            $this->buildService($client),
            'openPullRequest',
            ['acme', 'demo', 'my-account', 'fix/securescan-1', 'main', $scan]
        );

        $this->assertNull($result);
    }

    public function testBuildPullRequestBodyListsOnlyFindingsWithAnAcceptedFix(): void
    {
        $scan = $this->buildScanWithAcceptedFix();

        $body = $this->invokePrivate($this->buildService(new MockHttpClient()), 'buildPullRequestBody', [$scan]);

        $this->assertStringContainsString((string) $scan->getId(), $body);
        $this->assertStringContainsString('db.php', $body);
        $this->assertStringNotContainsString('pending.php', $body);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function buildService(MockHttpClient $client, string $token = 'gh-test-token'): GitHubPushService
    {
        return new GitHubPushService($client, $this->logger, $token);
    }

    private function trackingClient(int &$calls): MockHttpClient
    {
        return new MockHttpClient(function () use (&$calls): MockResponse {
            $calls++;

            return new MockResponse('{}');
        });
    }

    private function buildScan(?string $fixBranch, ?string $localPath, string $repositoryUrl = 'https://github.com/acme/demo.git'): Scan
    {
        $project = new Project();
        $project->setRepositoryUrl($repositoryUrl);
        if ($localPath !== null) {
            $project->setLocalPath($localPath);
        }

        $scan = new Scan();
        $scan->setProject($project);
        $scan->setFixBranch($fixBranch);

        return $scan;
    }

    private function buildScanWithAcceptedFix(): Scan
    {
        $scan = $this->buildScan('fix/securescan-1', $this->createTempDir());

        $accepted = new Finding();
        $accepted->setTool('securescan')->setSeverity(Finding::SEVERITY_HIGH)
            ->setOwaspCategory(Finding::OWASP_A05)->setTitle('Injection SQL')->setFilePath('db.php');
        $fix = new Fix();
        $fix->setProposedCode('fixed')->accept();
        $accepted->addFix($fix);
        $scan->addFinding($accepted);

        $pending = new Finding();
        $pending->setTool('securescan')->setSeverity(Finding::SEVERITY_LOW)
            ->setOwaspCategory(Finding::OWASP_A02)->setTitle('Config')->setFilePath('pending.php');
        $scan->addFinding($pending);

        return $scan;
    }

    private function invokePrivate(object $object, string $method, array $args = []): mixed
    {
        // setAccessible() est un no-op deprecated depuis PHP 8.1 : la Reflection
        // peut déjà invoquer les méthodes privées sans cet appel.
        return (new \ReflectionMethod($object, $method))->invoke($object, ...$args);
    }

    private function createTempDir(): string
    {
        $dir = sys_get_temp_dir() . '/securescan_test_' . bin2hex(random_bytes(8));
        mkdir($dir, 0777, true);
        $this->tempDirs[] = $dir;

        return $dir;
    }
}