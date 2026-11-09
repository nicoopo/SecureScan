<?php

namespace App\Tests\Service\Analyzer;

use App\Entity\Finding;
use PHPUnit\Framework\TestCase;

abstract class AnalyzerTestCase extends TestCase
{
    /** @var string[] */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDirectory($dir);
        }
        $this->tempDirs = [];
    }

    /**
     * Crée un mini-projet temporaire à partir d'un mapping chemin relatif => contenu,
     * et retourne le chemin absolu du répertoire créé.
     *
     * @param array<string, string> $files
     */
    protected function createProject(array $files): string
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

    protected function findByRuleId(array $findings, string $ruleId): ?Finding
    {
        foreach ($findings as $finding) {
            if ($finding->getRuleId() === $ruleId) {
                return $finding;
            }
        }

        return null;
    }

    /** @return Finding[] */
    protected function filterByRuleId(array $findings, string $ruleId): array
    {
        return array_values(array_filter(
            $findings,
            static fn (Finding $finding) => $finding->getRuleId() === $ruleId
        ));
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