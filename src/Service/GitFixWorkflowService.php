<?php

namespace App\Service;

use App\Entity\Scan;

/**
 * Gère la branche Git locale dédiée aux corrections d'un scan : création
 * (une fois par scan) et commit de chaque fix appliqué sur cette branche.
 */
class GitFixWorkflowService
{
    public function ensureFixBranch(Scan $scan): ?string
    {
        $projectPath = $scan->getProject()?->getLocalPath();
        if (!$projectPath || !is_dir($projectPath)) {
            return null;
        }

        $branch = $scan->getFixBranch();
        if ($branch === null) {
            $branch = 'fix/securescan-' . (new \DateTimeImmutable())->format('Y-m-d-His');
            $scan->setFixBranch($branch);
        }

        $this->checkoutBranch($projectPath, $branch);

        return $branch;
    }

    public function commitFix(Scan $scan, string $relativeFilePath, string $message): void
    {
        $projectPath = $scan->getProject()?->getLocalPath();
        if (!$projectPath || !is_dir($projectPath)) {
            return;
        }

        $path = escapeshellarg($projectPath);
        $file = escapeshellarg($relativeFilePath);
        $msg  = escapeshellarg($message);

        shell_exec(
            "cd {$path} && git -c safe.directory=* add {$file}"
            . " && git -c safe.directory=* -c user.email=securescan@localhost -c user.name=SecureScan commit -m {$msg} -q 2>&1"
        );
    }

    /** Bascule sur la branche si elle existe déjà, la crée sinon. */
    private function checkoutBranch(string $projectPath, string $branch): void
    {
        $path      = escapeshellarg($projectPath);
        $branchArg = escapeshellarg($branch);

        shell_exec("cd {$path} && (git -c safe.directory=* checkout {$branchArg} 2>/dev/null || git -c safe.directory=* checkout -b {$branchArg} 2>&1)");
    }
}