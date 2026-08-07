<?php

namespace App\Entity;

use App\Repository\FindingRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: FindingRepository::class)]
#[ORM\Index(columns: ['severity'], name: 'idx_finding_severity')]
#[ORM\Index(columns: ['owasp_category'], name: 'idx_finding_owasp')]
#[ORM\Index(columns: ['tool'], name: 'idx_finding_tool')]
class Finding
{
    // Sévérités
    public const SEVERITY_CRITICAL = 'critical';
    public const SEVERITY_HIGH     = 'high';
    public const SEVERITY_MEDIUM   = 'medium';
    public const SEVERITY_LOW      = 'low';

    // Outils sources
    public const TOOL_SEMGREP     = 'semgrep';
    public const TOOL_NPM_AUDIT   = 'npm_audit';
    public const TOOL_TRUFFLEHOG  = 'trufflehog';
    public const TOOL_ESLINT      = 'eslint';
    public const TOOL_PHPSTAN     = 'phpstan';

    // Catégories OWASP Top 10 : 2025
    public const OWASP_A01 = 'A01';
    public const OWASP_A02 = 'A02';
    public const OWASP_A03 = 'A03';
    public const OWASP_A04 = 'A04';
    public const OWASP_A05 = 'A05';
    public const OWASP_A06 = 'A06';
    public const OWASP_A07 = 'A07';
    public const OWASP_A08 = 'A08';
    public const OWASP_A09 = 'A09';
    public const OWASP_A10 = 'A10';

    public const OWASP_LABELS = [
        self::OWASP_A01 => 'Broken Access Control',
        self::OWASP_A02 => 'Security Misconfiguration',
        self::OWASP_A03 => 'Software Supply Chain Failures',
        self::OWASP_A04 => 'Cryptographic Failures',
        self::OWASP_A05 => 'Injection',
        self::OWASP_A06 => 'Insecure Design',
        self::OWASP_A07 => 'Authentication Failures',
        self::OWASP_A08 => 'Software/Data Integrity Failures',
        self::OWASP_A09 => 'Logging & Alerting Failures',
        self::OWASP_A10 => 'Mishandling of Exceptional Conditions',
    ];

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'findings')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?Scan $scan = null;

    /** Outil qui a détecté la vulnérabilité */
    #[ORM\Column(length: 50)]
    private string $tool;

    #[ORM\Column(length: 20)]
    private string $severity = self::SEVERITY_MEDIUM;

    /** Catégorie OWASP Top 10 (A01 … A10) */
    #[ORM\Column(length: 3)]
    private string $owaspCategory;

    /** Chemin du fichier relatif à la racine du projet */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $filePath = null;

    /** Numéro de ligne dans le fichier */
    #[ORM\Column(nullable: true)]
    private ?int $line = null;

    /** Identifiant de la règle dans l'outil source (ex: semgrep rule id) */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $ruleId = null;

    /** Titre court de la vulnérabilité */
    #[ORM\Column(length: 255)]
    private string $title;

    /** Description détaillée */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $description = null;

    /** Extrait du code source concerné */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $codeSnippet = null;

    /** Payload JSON brut retourné par l'outil */
    #[ORM\Column(type: Types::JSON, nullable: true)]
    private ?array $rawData = null;

    #[ORM\OneToMany(mappedBy: 'finding', targetEntity: Fix::class, cascade: ['persist', 'remove'], orphanRemoval: true)]
    private Collection $fixes;

    public function __construct()
    {
        $this->fixes = new ArrayCollection();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    public function getOwaspLabel(): string
    {
        return self::OWASP_LABELS[$this->owaspCategory] ?? $this->owaspCategory;
    }

    public function getSeverityWeight(): int
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 4,
            self::SEVERITY_HIGH     => 3,
            self::SEVERITY_MEDIUM   => 2,
            self::SEVERITY_LOW      => 1,
            default                 => 0,
        };
    }

    public function getAcceptedFix(): ?Fix
    {
        foreach ($this->fixes as $fix) {
            if ($fix->getStatus() === Fix::STATUS_ACCEPTED) {
                return $fix;
            }
        }
        return null;
    }

    public function hasPendingFix(): bool
    {
        return $this->getPendingFix() !== null;
    }

    public function getPendingFix(): ?Fix
    {
        foreach ($this->fixes as $fix) {
            if ($fix->getStatus() === Fix::STATUS_PENDING) {
                return $fix;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public function getId(): ?int { return $this->id; }

    public function getScan(): ?Scan { return $this->scan; }
    public function setScan(?Scan $scan): static { $this->scan = $scan; return $this; }

    public function getTool(): string { return $this->tool; }
    public function setTool(string $tool): static { $this->tool = $tool; return $this; }

    public function getSeverity(): string { return $this->severity; }
    public function setSeverity(string $severity): static { $this->severity = $severity; return $this; }

    public function getOwaspCategory(): string { return $this->owaspCategory; }
    public function setOwaspCategory(string $cat): static { $this->owaspCategory = $cat; return $this; }

    public function getFilePath(): ?string { return $this->filePath; }
    public function setFilePath(?string $path): static { $this->filePath = $path; return $this; }

    public function getLine(): ?int { return $this->line; }
    public function setLine(?int $line): static { $this->line = $line; return $this; }

    public function getRuleId(): ?string { return $this->ruleId; }
    public function setRuleId(?string $id): static { $this->ruleId = $id; return $this; }

    public function getTitle(): string { return $this->title; }
    public function setTitle(string $title): static { $this->title = $title; return $this; }

    public function getDescription(): ?string { return $this->description; }
    public function setDescription(?string $desc): static { $this->description = $desc; return $this; }

    public function getCodeSnippet(): ?string { return $this->codeSnippet; }
    public function setCodeSnippet(?string $code): static { $this->codeSnippet = $code; return $this; }

    public function getRawData(): ?array { return $this->rawData; }
    public function setRawData(?array $data): static { $this->rawData = $data; return $this; }

    /** @return Collection<int, Fix> */
    public function getFixes(): Collection { return $this->fixes; }

    public function addFix(Fix $fix): static
    {
        if (!$this->fixes->contains($fix)) {
            $this->fixes->add($fix);
            $fix->setFinding($this);
        }
        return $this;
    }
public function __toString(): string
{
    return $this->title;
}
}
