<?php

namespace App\Entity;

use App\Repository\ScanReportRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ScanReportRepository::class)]
class ScanReport
{
    public const FORMAT_HTML = 'html';
    public const FORMAT_PDF  = 'pdf';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\OneToOne(inversedBy: 'report')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?Scan $scan = null;

    /** Contenu HTML du rapport */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $htmlContent = null;

    /** Chemin vers le fichier PDF généré */
    #[ORM\Column(length: 512, nullable: true)]
    private ?string $pdfPath = null;

    /** Résumé JSON exportable (utile pour les clients CyberSafe) */
    #[ORM\Column(type: Types::JSON, nullable: true)]
    private ?array $summary = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $generatedAt;

    public function __construct()
    {
        $this->generatedAt = new \DateTimeImmutable();
    }

    public function getId(): ?int { return $this->id; }

    public function getScan(): ?Scan { return $this->scan; }
    public function setScan(?Scan $scan): static { $this->scan = $scan; return $this; }

    public function getHtmlContent(): ?string { return $this->htmlContent; }
    public function setHtmlContent(?string $html): static { $this->htmlContent = $html; return $this; }

    public function getPdfPath(): ?string { return $this->pdfPath; }
    public function setPdfPath(?string $path): static { $this->pdfPath = $path; return $this; }

    public function getSummary(): ?array { return $this->summary; }
    public function setSummary(?array $data): static { $this->summary = $data; return $this; }

    public function getGeneratedAt(): \DateTimeImmutable { return $this->generatedAt; }
    public function __toString(): string
{
    return $this->name;
}
}
