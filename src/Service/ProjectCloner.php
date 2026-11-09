<?php
namespace App\Service;

use App\Entity\Project;

class ProjectCloner{
    private string $workDir;

    public function __construct(string $workDir = '/var/www/html/var/projects'){
        $this->workDir = $workDir;
    }

    public function clone(Project $project): string{
        $dest = $this->workDir . '/' . uniqid('project_', true);
        @mkdir($dest, 0755, true);

        if ($project->getSource() === Project::SOURCE_GIT) {
            $url = escapeshellarg($project->getRepositoryUrl());
            $destArg = escapeshellarg($dest);
            exec("git clone --depth=1 {$url} {$destArg} 2>&1", $output, $code);

            if ($code !== 0) {
                throw new \RuntimeException('Échec du clonage Git : ' . implode("\n", $output));
            }
        } else {
            $zipPath = $project->getZipPath();
            if (!$zipPath || !file_exists($zipPath)) {
                throw new \RuntimeException('Archive ZIP introuvable : ' . $zipPath);
            }

            $zip = new \ZipArchive();
            if ($zip->open($zipPath) !== true) {
                throw new \RuntimeException('Impossible d\'ouvrir l\'archive ZIP.');
            }
            $zip->extractTo($dest);
            $zip->close();
        }

        return $dest;
    }

    /** Détecte le langage principal d'un projet cloné à partir de ses fichiers de manifeste racine. */
    public function detectLanguage(string $projectPath): string
    {
        $markers = [
            'composer.json'    => Project::LANGUAGE_PHP,
            'package.json'     => Project::LANGUAGE_JAVASCRIPT,
            'requirements.txt' => Project::LANGUAGE_PYTHON,
            'pyproject.toml'   => Project::LANGUAGE_PYTHON,
            'go.mod'           => Project::LANGUAGE_GO,
            'Gemfile'          => Project::LANGUAGE_RUBY,
            'pom.xml'          => Project::LANGUAGE_JAVA,
            'build.gradle'     => Project::LANGUAGE_JAVA,
        ];

        foreach ($markers as $file => $language) {
            if (file_exists($projectPath . '/' . $file)) {
                return $language;
            }
        }

        return Project::LANGUAGE_UNKNOWN;
    }
}
