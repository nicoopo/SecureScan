<?php

namespace App\Entity;

use App\Repository\ScanRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ScanRepository::class)]
class Scan
{
    public const STATUS_PENDING  = 'pending';
    public const STATUS_RUNNING  = 'running';
    public const STATUS_DONE     = 'done';
    public const STATUS_FAILED   = 'failed';

    public const GRADE_A = 'A';
    public const GRADE_B = 'B';
    public const GRADE_C = 'C';
    public const GRADE_D = 'D';
    public const GRADE_F = 'F';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'scans')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?Project $project = null;

    #[ORM\Column(length: 20)]
    private string $status = self::STATUS_PENDING;

    /** Score de 0 à 100 */
    #[ORM\Column(nullable: true)]
    private ?int $score = null;

    /** Grade calculé depuis le score (A/B/C/D/F) */
    #[ORM\Column(length: 1, nullable: true)]
    private ?string $grade = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $startedAt;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, nullable: true)]
    private ?\DateTimeImmutable $finishedAt = null;

    /** Message d'erreur si status = failed */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $errorMessage = null;

    /** Branche Git créée pour les corrections (ex: fix/securescan-2026-05-10) */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $fixBranch = null;

    #[ORM\OneToMany(mappedBy: 'scan', targetEntity: Finding::class, cascade: ['persist', 'remove'], orphanRemoval: true)]
    private Collection $findings;

    #[ORM\OneToOne(mappedBy: 'scan', targetEntity: ScanReport::class, cascade: ['persist', 'remove'], orphanRemoval: true)]
    private ?ScanReport $report = null;

    #[ORM\ManyToOne(inversedBy: 'scans')]
    #[ORM\JoinColumn(nullable: true)]
    private ?User $user = null;

    public function __construct()
    {
        $this->findings  = new ArrayCollection();
        $this->startedAt = new \DateTimeImmutable();
    }

    // -------------------------------------------------------------------------
    // Helpers métier
    // -------------------------------------------------------------------------

    public function finish(): void
    {
        $this->status     = self::STATUS_DONE;
        $this->finishedAt = new \DateTimeImmutable();
        $this->computeScore();
    }

    public function fail(string $message): void
    {
        $this->status       = self::STATUS_FAILED;
        $this->finishedAt   = new \DateTimeImmutable();
        $this->errorMessage = $message;
    }

    /**
     * Calcule le score (0-100) et la note (A-F) en fonction des findings.
     * Poids : critique = 25, haute = 10, moyenne = 4, basse = 1.
     */
    public function computeScore(): void
    {
        $penalties = 0;
        foreach ($this->findings as $finding) {
            $penalties += match ($finding->getSeverity()) {
                Finding::SEVERITY_CRITICAL => 25,
                Finding::SEVERITY_HIGH     => 10,
                Finding::SEVERITY_MEDIUM   => 4,
                Finding::SEVERITY_LOW      => 1,
                default                    => 0,
            };
        }

        $this->score = max(0, 100 - $penalties);
        $this->grade = match (true) {
            $this->score >= 90 => self::GRADE_A,
            $this->score >= 75 => self::GRADE_B,
            $this->score >= 60 => self::GRADE_C,
            $this->score >= 40 => self::GRADE_D,
            default            => self::GRADE_F,
        };
    }

    /** Compte les findings par sévérité */
    public function countBySeverity(): array
    {
        $counts = [
            Finding::SEVERITY_CRITICAL => 0,
            Finding::SEVERITY_HIGH     => 0,
            Finding::SEVERITY_MEDIUM   => 0,
            Finding::SEVERITY_LOW      => 0,
        ];
        foreach ($this->findings as $f) {
            if (isset($counts[$f->getSeverity()])) {
                $counts[$f->getSeverity()]++;
            }
        }
        return $counts;
    }

    /** Compte les findings par catégorie OWASP */
    public function countByOwasp(): array
    {
        $counts = [];
        foreach ($this->findings as $f) {
            $cat = $f->getOwaspCategory();
            $counts[$cat] = ($counts[$cat] ?? 0) + 1;
        }
        return $counts;
    }

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public function getId(): ?int { return $this->id; }

    public function getProject(): ?Project { return $this->project; }
    public function setProject(?Project $project): static { $this->project = $project; return $this; }

    public function getStatus(): string { return $this->status; }
    public function setStatus(string $status): static { $this->status = $status; return $this; }

    public function getScore(): ?int { return $this->score; }
    public function setScore(?int $score): static { $this->score = $score; return $this; }

    public function getGrade(): ?string { return $this->grade; }
    public function setGrade(?string $grade): static { $this->grade = $grade; return $this; }

    public function getStartedAt(): \DateTimeImmutable { return $this->startedAt; }

    public function getFinishedAt(): ?\DateTimeImmutable { return $this->finishedAt; }
    public function setFinishedAt(?\DateTimeImmutable $dt): static { $this->finishedAt = $dt; return $this; }

    public function getErrorMessage(): ?string { return $this->errorMessage; }

    public function getFixBranch(): ?string { return $this->fixBranch; }
    public function setFixBranch(?string $branch): static { $this->fixBranch = $branch; return $this; }

    /** @return Collection<int, Finding> */
    public function getFindings(): Collection { return $this->findings; }

    public function addFinding(Finding $finding): static
    {
        if (!$this->findings->contains($finding)) {
            $this->findings->add($finding);
            $finding->setScan($this);
        }
        return $this;
    }

    public function getReport(): ?ScanReport { return $this->report; }
    public function setReport(?ScanReport $report): static { $this->report = $report; return $this; }

    public function getUser(): ?User { return $this->user; }
    public function setUser(?User $user): static { $this->user = $user; return $this; }
    public function isDone(): bool    { return $this->status === self::STATUS_DONE; }
    public function isPending(): bool { return $this->status === self::STATUS_PENDING; }
    public function isFailed(): bool  { return $this->status === self::STATUS_FAILED; }
public function __toString(): string
{
    return 'Scan #' . $this->id;
}
}
