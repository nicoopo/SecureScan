<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A010Analyzer
{
    private const TOOL = 'securescan';

    private const PATTERNS = [
        [
            'id'          => 'a10.exception.empty_catch',
            'regex'       => '/catch\s*\([^)]+\)\s*\{\s*\}/i',
            'title'       => 'Bloc catch vide',
            'description' => 'Un bloc catch vide absorbe silencieusement les erreurs sans les logger ni les traiter. Les exceptions doivent être loggées.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'java'],
        ],
        [
            'id'          => 'a10.exception.expose_message',
            'regex'       => '/echo\s+\$e->getMessage\(\)|print\s+\$e->getMessage\(\)/i',
            'title'       => 'Message d\'exception exposé à l\'utilisateur',
            'description' => 'Le message d\'exception est affiché directement à l\'utilisateur. Cela peut exposer des informations sensibles sur l\'architecture interne.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a10.exception.expose_message.python',
            'regex'       => '/print\s*\(\s*(?:e|ex|exc|error)\s*\)/i',
            'title'       => 'Message d\'exception exposé à l\'utilisateur',
            'description' => 'L\'exception est affichée directement (print). Cela peut exposer des informations sensibles sur l\'architecture interne. Logger l\'exception plutôt que de l\'afficher.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a10.exception.expose_message.ruby',
            'regex'       => '/puts\s+(?:e|ex|exception)\.message\b/i',
            'title'       => 'Message d\'exception exposé à l\'utilisateur',
            'description' => 'Le message d\'exception est affiché directement (puts). Cela peut exposer des informations sensibles. Logger l\'exception plutôt que de l\'afficher.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a10.exception.expose_message.java',
            'regex'       => '/System\.out\.print(?:ln)?\s*\(\s*e\.getMessage\(\)\s*\)/i',
            'title'       => 'Message d\'exception exposé à l\'utilisateur',
            'description' => 'Le message d\'exception est affiché directement sur la sortie standard. Cela peut exposer des informations sensibles. Utiliser un logger plutôt que System.out.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a10.exception.expose_message.go',
            'regex'       => '/fmt\.Print(?:ln)?\s*\(\s*err\s*\)/i',
            'title'       => 'Erreur exposée à l\'utilisateur',
            'description' => 'L\'erreur est affichée directement sur la sortie standard. Cela peut exposer des informations sensibles. Utiliser un logger structuré plutôt que fmt.Print.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['go'],
        ],
        [
            'id'          => 'a10.exception.expose_trace',
            'regex'       => '/echo\s+\$e->getTraceAsString\(\)|print\s+\$e->getTraceAsString\(\)/i',
            'title'       => 'Stack trace exposée à l\'utilisateur',
            'description' => 'La stack trace est affichée directement. Elle révèle la structure interne du code, les chemins de fichiers et les versions de bibliothèques.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a10.exception.expose_trace.python',
            'regex'       => '/traceback\.print_exc\s*\(\s*\)/i',
            'title'       => 'Stack trace exposée à l\'utilisateur',
            'description' => 'traceback.print_exc() affiche la stack trace complète. Elle révèle la structure interne du code. Logger la trace plutôt que de l\'afficher à l\'utilisateur.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a10.exception.expose_trace.ruby',
            'regex'       => '/puts\s+e\.backtrace/i',
            'title'       => 'Stack trace exposée à l\'utilisateur',
            'description' => 'La backtrace de l\'exception est affichée directement. Elle révèle la structure interne du code. Logger la trace plutôt que de l\'afficher.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a10.exception.expose_trace.java',
            'regex'       => '/\.printStackTrace\s*\(\s*\)/i',
            'title'       => 'Stack trace exposée à l\'utilisateur',
            'description' => 'printStackTrace() écrit la stack trace sur la sortie standard/erreur, où elle peut finir exposée à l\'utilisateur ou dans des logs non sécurisés. Utiliser un logger applicatif.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a10.exception.die_with_message',
            'regex'       => '/die\s*\(\s*\$|exit\s*\(\s*\$/i',
            'title'       => 'die()/exit() avec variable exposée',
            'description' => 'die() ou exit() affiche une variable directement. Peut exposer des informations sensibles en cas d\'erreur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a10.exception.die_with_message.python',
            'regex'       => '/sys\.exit\s*\(\s*(?:f[\'"]|[a-zA-Z_])/i',
            'title'       => 'sys.exit() avec message exposé',
            'description' => 'sys.exit() est appelé avec un message dynamique. Peut exposer des informations sensibles en cas d\'erreur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a10.exception.die_with_message.ruby',
            'regex'       => '/abort\s*\(?\s*(?:e|ex|error|msg)/i',
            'title'       => 'abort() avec message exposé',
            'description' => 'abort() est appelé avec un message dynamique. Peut exposer des informations sensibles en cas d\'erreur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a10.exception.error_reporting_off',
            'regex'       => '/error_reporting\s*\(\s*0\s*\)/i',
            'title'       => 'Erreurs PHP masquées sans logging',
            'description' => 'error_reporting(0) masque toutes les erreurs. Les erreurs doivent être loggées côté serveur même si elles ne sont pas affichées.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a10.exception.catch_and_continue',
            'regex'       => '/catch\s*\([^)]+\)\s*\{\s*\/\//i',
            'title'       => 'Exception ignorée avec commentaire',
            'description' => 'Une exception est catchée avec seulement un commentaire. Les exceptions doivent être loggées ou traitées correctement.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php', 'java'],
        ],
        [
            'id'          => 'a10.exception.generic_exception',
            'regex'       => '/catch\s*\(\s*Exception\s+\$e\s*\)/i',
            'title'       => 'Catch générique sur Exception',
            'description' => 'Attraper toutes les exceptions avec Exception est trop générique. Utiliser des exceptions spécifiques pour un meilleur contrôle du flux d\'erreur.',
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a10.exception.generic_exception.java',
            'regex'       => '/catch\s*\(\s*Exception\s+\w+\s*\)/i',
            'title'       => 'Catch générique sur Exception',
            'description' => 'Attraper toutes les exceptions avec Exception est trop générique. Utiliser des exceptions spécifiques pour un meilleur contrôle du flux d\'erreur.',
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a10.exception.generic_exception.python',
            'regex'       => '/except\s+Exception(?:\s+as\s+\w+)?\s*:/i',
            'title'       => 'Catch générique sur Exception',
            'description' => 'Attraper toutes les exceptions avec except Exception est trop générique. Utiliser des exceptions spécifiques pour un meilleur contrôle du flux d\'erreur.',
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a10.exception.generic_exception.ruby',
            'regex'       => '/^\s*rescue(?:\s*=>\s*\w+)?\s*$/',
            'title'       => 'Catch générique sur StandardError',
            'description' => 'Un rescue sans classe explicite intercepte StandardError, ce qui est trop générique. Préciser la classe d\'exception attendue.',
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a10.exception.var_dump_exception',
            'regex'       => '/var_dump\s*\(\s*\$e\s*\)|var_export\s*\(\s*\$e\s*\)/i',
            'title'       => 'var_dump() d\'une exception en production',
            'description' => 'var_dump() d\'une exception expose toute la structure interne de l\'erreur. Supprimer en production.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
    ];

    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {
            $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            $relative = ltrim(substr($filePath, strlen(rtrim($projectPath, '/\\'))), '/\\');
            $lines    = file($filePath, FILE_IGNORE_NEW_LINES);

            if ($lines === false) continue;

            foreach (self::PATTERNS as $pattern) {
                if (!in_array($ext, $pattern['extensions'], true)) continue;

                foreach ($lines as $index => $lineContent) {
                    if (preg_match($pattern['regex'], $lineContent)) {
                        $finding = new Finding();
                        $finding
                            ->setScan($scan)
                            ->setTool(self::TOOL)
                            ->setSeverity($pattern['severity'])
                            ->setOwaspCategory(Finding::OWASP_A10)
                            ->setRuleId($pattern['id'])
                            ->setTitle($pattern['title'])
                            ->setDescription($pattern['description'])
                            ->setFilePath($relative)
                            ->setLine($index + 1)
                            ->setCodeSnippet(trim($lineContent));
                        $findings[] = $finding;
                    }
                }
            }
        }

        return $findings;
    }

    private function collectFiles(string $dir): \Generator
    {
        if (!is_dir($dir)) return;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            if (str_contains($path, '/vendor/') || str_contains($path, '/node_modules/') || str_contains($path, '/.git/')) continue;
            yield $path;
        }
    }
}
