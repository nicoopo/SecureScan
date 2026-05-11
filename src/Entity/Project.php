<?php

namespace App\Entity;

use App\Repository\ProjectRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ProjectRepository::class)]
#[ORM\HasLifecycleCallbacks]
class Project
{
    public const LANGUAGE_PHP        = 'php';
    public const LANGUAGE_JAVASCRIPT = 'javascript';
    public const LANGUAGE_PYTHON     = 'python';
    public const LANGUAGE_NODEJS     = 'nodejs';
    public const LANGUAGE_UNKNOWN    = 'unknown';

    public const SOURCE_GIT = 'git';
    public const SOURCE_ZIP = 'zip';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    /** Propriétaire du projet — ne voit que ses propres repos */
    #[ORM\ManyToOne(inversedBy: 'projects')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?User $owner = null;

    #[ORM\Column(length: 255)]
    private string $name;

    /** URL du repo Git ou null si upload ZIP */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $repositoryUrl = null;

    /** Chemin local vers l'archive ZIP uploadée */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $zipPath = null;

    /** Chemin local vers le code cloné/extrait */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $localPath = null;

    #[ORM\Column(length: 20)]
    private string $source = self::SOURCE_GIT; // 'git' | 'zip'

    #[ORM\Column(length: 30)]
    private string $language = self::LANGUAGE_UNKNOWN;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, nullable: true)]
    private ?\DateTimeImmutable $updatedAt = null;

    #[ORM\OneToMany(mappedBy: 'project', targetEntity: Scan::class, cascade: ['persist', 'remove'], orphanRemoval: true)]
    #[ORM\OrderBy(['startedAt' => 'DESC'])]
    private Collection $scans;

    public function __construct()
    {
        $this->scans     = new ArrayCollection();
        $this->createdAt = new \DateTimeImmutable();
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
    }

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public function getId(): ?int { return $this->id; }

    public function getOwner(): ?User { return $this->owner; }
    public function setOwner(?User $owner): static { $this->owner = $owner; return $this; }

    public function getName(): string { return $this->name; }
    public function setName(string $name): static { $this->name = $name; return $this; }

    public function getRepositoryUrl(): ?string { return $this->repositoryUrl; }
    public function setRepositoryUrl(?string $url): static { $this->repositoryUrl = $url; return $this; }

    public function getZipPath(): ?string { return $this->zipPath; }
    public function setZipPath(?string $path): static { $this->zipPath = $path; return $this; }

    public function getLocalPath(): ?string { return $this->localPath; }
    public function setLocalPath(?string $path): static { $this->localPath = $path; return $this; }

    public function getSource(): string { return $this->source; }
    public function setSource(string $source): static { $this->source = $source; return $this; }

    public function getLanguage(): string { return $this->language; }
    public function setLanguage(string $language): static { $this->language = $language; return $this; }

    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getUpdatedAt(): ?\DateTimeImmutable { return $this->updatedAt; }

    /** @return Collection<int, Scan> */
    public function getScans(): Collection { return $this->scans; }

    public function addScan(Scan $scan): static
    {
        if (!$this->scans->contains($scan)) {
            $this->scans->add($scan);
            $scan->setProject($this);
        }
        return $this;
    }

    public function removeScan(Scan $scan): static
    {
        if ($this->scans->removeElement($scan) && $scan->getProject() === $this) {
            $scan->setProject(null);
        }
        return $this;
    }

    /** Retourne le dernier scan exécuté */
    public function getLatestScan(): ?Scan
    {
        return $this->scans->first() ?: null;
    }
}
