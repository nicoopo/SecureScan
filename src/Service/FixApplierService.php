<?php

namespace App\Service;

use App\Entity\Fix;

/**
 * Applique une correction acceptée sur le fichier réel du projet scanné,
 * de façon non-destructive : la suggestion est insérée en commentaire
 * juste au-dessus de la ligne concernée, le code existant n'est jamais
 * modifié ni supprimé.
 *
 * Les templates de FixGeneratorService sont génériques (noms de variables
 * placeholder) : les réécrire directement dans le fichier casserait
 * probablement la syntaxe du code réel, d'où ce choix de rester en commentaire.
 */
class FixApplierService
{
    private const LINE_COMMENT_EXTENSIONS = [
        'php', 'phtml', 'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'java', 'go', 'c', 'cpp', 'h', 'hpp', 'cs',
    ];

    private const HASH_COMMENT_EXTENSIONS = ['py', 'rb', 'sh', 'yml', 'yaml', 'txt'];

    private const HASH_COMMENT_BASENAMES = ['Gemfile', 'Dockerfile', 'Makefile'];

    private const BLOCK_COMMENT_EXTENSIONS = ['xml', 'html', 'htm'];

    private const JSON_EXTENSIONS = ['json'];

    /**
     * @return array{applied: bool, message: string}
     */
    public function apply(Fix $fix): array
    {
        $finding = $fix->getFinding();
        $project = $finding?->getScan()?->getProject();
        $localPath = $project?->getLocalPath();
        $relativePath = $fix->getFilePath();

        if (!$localPath || !$relativePath) {
            return ['applied' => false, 'message' => "Chemin du fichier introuvable, rien n'a été écrit."];
        }

        $fullPath = rtrim($localPath, '/\\') . '/' . ltrim($relativePath, '/\\');
        $realProjectPath = realpath($localPath);
        $realFilePath = realpath($fullPath);

        if (!$realProjectPath || !$realFilePath || !str_starts_with($realFilePath, $realProjectPath)) {
            return ['applied' => false, 'message' => "Fichier introuvable ou en dehors du projet, rien n'a été écrit."];
        }

        if (in_array(strtolower(pathinfo($realFilePath, PATHINFO_EXTENSION)), self::JSON_EXTENSIONS, true)) {
            return $this->applyJsonAnnotation($fix, $realFilePath, $relativePath);
        }

        $commentStyle = $this->resolveCommentStyle($realFilePath);
        if ($commentStyle === null) {
            return ['applied' => false, 'message' => 'Format de fichier non pris en charge pour une annotation (ex : JSON).'];
        }

        $lines = file($realFilePath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return ['applied' => false, 'message' => 'Impossible de lire le fichier.'];
        }

        $targetIndex = $this->locateInsertionIndex($lines, $fix);
        $annotation = $this->buildAnnotation($fix, $commentStyle);

        array_splice($lines, $targetIndex, 0, $annotation);

        if (file_put_contents($realFilePath, implode(PHP_EOL, $lines) . PHP_EOL) === false) {
            return ['applied' => false, 'message' => "Échec de l'écriture du fichier."];
        }

        return ['applied' => true, 'message' => "Suggestion insérée dans {$relativePath}."];
    }

    /**
     * @param string[] $lines
     * @return string[]
     */
    private function locateInsertionIndex(array $lines, Fix $fix): int
    {
        $lineStart = $fix->getLineStart();
        $default = $lineStart ? max(0, $lineStart - 1) : 0;
        $default = min($default, count($lines));

        $original = trim((string) $fix->getOriginalCode());
        if ($original === '') {
            return $default;
        }

        $window = 3;
        $from = max(0, $default - $window);
        $to   = min(count($lines) - 1, $default + $window);

        for ($i = $from; $i <= $to; $i++) {
            if (trim($lines[$i]) === $original) {
                return $i;
            }
        }

        return $default;
    }

    /**
     * @return string[]
     */
    private function buildAnnotation(Fix $fix, array $commentStyle): array
    {
        [$prefix, $suffix] = $commentStyle;
        $ruleId = $fix->getFinding()?->getRuleId();
        $header = '[SecureScan] Correction proposée' . ($ruleId ? " ({$ruleId})" : '');

        $body = [$header];
        if ($fix->getExplanation()) {
            $body[] = $fix->getExplanation();
        }
        $body[] = '';
        $body = array_merge($body, explode("\n", $fix->getProposedCode()));

        return array_map(
            static fn (string $line): string => $suffix ? "{$prefix} {$line} {$suffix}" : "{$prefix} {$line}",
            $body
        );
    }

    /**
     * @return array{0: string, 1: ?string}|null
     */
    private function resolveCommentStyle(string $filePath): ?array
    {
        $basename = basename($filePath);
        if (in_array($basename, self::HASH_COMMENT_BASENAMES, true)) {
            return ['#', null];
        }

        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        return match (true) {
            in_array($ext, self::BLOCK_COMMENT_EXTENSIONS, true) => ['<!--', '-->'],
            in_array($ext, self::HASH_COMMENT_EXTENSIONS, true)  => ['#', null],
            in_array($ext, self::LINE_COMMENT_EXTENSIONS, true)  => ['//', null],
            default => null,
        };
    }

    /**
     * JSON n'a pas de syntaxe de commentaire standard : on insère une clé
     * "// ..." (convention répandue, ex. tsconfig.json) juste après l'accolade
     * ouvrante, ce qui reste du JSON valide sans dépendre de la position exacte
     * de la ligne vulnérable dans la structure.
     */
    private function applyJsonAnnotation(Fix $fix, string $realFilePath, string $relativePath): array
    {
        $lines = file($realFilePath, FILE_IGNORE_NEW_LINES);
        if ($lines === false || !isset($lines[0]) || !str_contains($lines[0], '{')) {
            return ['applied' => false, 'message' => "Structure JSON inattendue, rien n'a été écrit."];
        }

        $ruleId = $fix->getFinding()?->getRuleId();
        $key = '// [SecureScan] Correction proposée' . ($ruleId ? " ({$ruleId})" : '');
        $value = trim(($fix->getExplanation() ? $fix->getExplanation() . ' — ' : '') . $fix->getProposedCode());

        $annotationLine = sprintf(
            '  %s: %s,',
            json_encode($key, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        );

        array_splice($lines, 1, 0, [$annotationLine]);

        if (file_put_contents($realFilePath, implode(PHP_EOL, $lines) . PHP_EOL) === false) {
            return ['applied' => false, 'message' => "Échec de l'écriture du fichier."];
        }

        return ['applied' => true, 'message' => "Suggestion insérée en tête de {$relativePath}."];
    }
}
