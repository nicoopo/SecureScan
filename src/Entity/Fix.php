<?php

namespace App\Entity;

use App\Repository\FixRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: FixRepository::class)]
class Fix
{
    public const STATUS_PENDING  = 'pending';
    public const STATUS_ACCEPTED = 'accepted';
    public const STATUS_REJECTED = 'rejected';

    public const TYPE_TEMPLATE = 'template'; // correction prédéfinie
    public const TYPE_AI       = 'ai';       // générée par LLM

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'fixes')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?Finding $finding = null;

    /** 'template' ou 'ai' */
    #[ORM\Column(length: 20)]
    private string $type = self::TYPE_TEMPLATE;

    #[ORM\Column(length: 20)]
    private string $status = self::STATUS_PENDING;

    /** Code original (avant correction) */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $originalCode = null;

    /** Code corrigé proposé */
    #[ORM\Column(type: Types::TEXT)]
    private string $proposedCode;

    /**
     * Explication pédagogique de la correction.
     * Toujours renseigné pour les fixes IA, optionnel pour les templates.
     */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $explanation = null;

    /** Chemin du fichier à modifier */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $filePath = null;

    /** Ligne de début dans le fichier */
    #[ORM\Column(nullable: true)]
    private ?int $lineStart = null;

    /** Ligne de fin dans le fichier */
    #[ORM\Column(nullable: true)]
    private ?int $lineEnd = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, nullable: true)]
    private ?\DateTimeImmutable $decidedAt = null;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    public function accept(): void
    {
        $this->status    = self::STATUS_ACCEPTED;
        $this->decidedAt = new \DateTimeImmutable();
    }

    public function reject(): void
    {
        $this->status    = self::STATUS_REJECTED;
        $this->decidedAt = new \DateTimeImmutable();
    }

    public function isPending(): bool  { return $this->status === self::STATUS_PENDING; }
    public function isAccepted(): bool { return $this->status === self::STATUS_ACCEPTED; }
    public function isAi(): bool       { return $this->type === self::TYPE_AI; }

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public function getId(): ?int { return $this->id; }

    public function getFinding(): ?Finding { return $this->finding; }
    public function setFinding(?Finding $finding): static { $this->finding = $finding; return $this; }

    public function getType(): string { return $this->type; }
    public function setType(string $type): static { $this->type = $type; return $this; }

    public function getStatus(): string { return $this->status; }
    public function setStatus(string $status): static { $this->status = $status; return $this; }

    public function getOriginalCode(): ?string { return $this->originalCode; }
    public function setOriginalCode(?string $code): static { $this->originalCode = $code; return $this; }

    public function getProposedCode(): string { return $this->proposedCode; }
    public function setProposedCode(string $code): static { $this->proposedCode = $code; return $this; }

    public function getExplanation(): ?string { return $this->explanation; }
    public function setExplanation(?string $text): static { $this->explanation = $text; return $this; }

    public function getFilePath(): ?string { return $this->filePath; }
    public function setFilePath(?string $path): static { $this->filePath = $path; return $this; }

    public function getLineStart(): ?int { return $this->lineStart; }
    public function setLineStart(?int $line): static { $this->lineStart = $line; return $this; }

    public function getLineEnd(): ?int { return $this->lineEnd; }
    public function setLineEnd(?int $line): static { $this->lineEnd = $line; return $this; }

    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getDecidedAt(): ?\DateTimeImmutable { return $this->decidedAt; }
 public function __toString(): string
{
    return sprintf(
        '%s - %s',
        $this->type,
        $this->status
    );
}
}
