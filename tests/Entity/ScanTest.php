<?php

namespace App\Tests\Entity;

use App\Entity\Finding;
use App\Entity\Scan;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ScanTest extends TestCase
{
    public function testNoFindingsGivesPerfectScoreAndGradeA(): void
    {
        $scan = new Scan();

        $scan->computeScore();

        $this->assertSame(100, $scan->getScore());
        $this->assertSame(Scan::GRADE_A, $scan->getGrade());
    }

    /**
     * @param string[] $severities
     */
    #[DataProvider('severityComboProvider')]
    public function testScoreAndGradeFromSeverityCombination(array $severities, int $expectedScore, string $expectedGrade): void
    {
        $scan = $this->scanWithSeverities($severities);

        $scan->computeScore();

        $this->assertSame($expectedScore, $scan->getScore());
        $this->assertSame($expectedGrade, $scan->getGrade());
    }

    public static function severityComboProvider(): iterable
    {
        // Poids : critique = 25, haute = 10, moyenne = 4, basse = 1.
        yield 'score 90 -> A (borne basse de A)' => [
            [Finding::SEVERITY_HIGH], 90, Scan::GRADE_A,
        ];
        yield 'score 89 -> B (juste sous la borne de A)' => [
            [Finding::SEVERITY_HIGH, Finding::SEVERITY_LOW], 89, Scan::GRADE_B,
        ];
        yield 'score 75 -> B (borne basse de B)' => [
            [Finding::SEVERITY_CRITICAL], 75, Scan::GRADE_B,
        ];
        yield 'score 74 -> C (juste sous la borne de B)' => [
            [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_LOW], 74, Scan::GRADE_C,
        ];
        yield 'score 60 -> C (borne basse de C)' => [
            [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_HIGH, Finding::SEVERITY_MEDIUM, Finding::SEVERITY_LOW], 60, Scan::GRADE_C,
        ];
        yield 'score 59 -> D (juste sous la borne de C)' => [
            [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_HIGH, Finding::SEVERITY_MEDIUM, Finding::SEVERITY_LOW, Finding::SEVERITY_LOW], 59, Scan::GRADE_D,
        ];
        yield 'score 40 -> D (borne basse de D)' => [
            [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_CRITICAL, Finding::SEVERITY_HIGH], 40, Scan::GRADE_D,
        ];
        yield 'score 39 -> F (juste sous la borne de D)' => [
            [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_CRITICAL, Finding::SEVERITY_HIGH, Finding::SEVERITY_LOW], 39, Scan::GRADE_F,
        ];
    }

    public function testScoreIsFlooredAtZeroWhenPenaltiesExceedHundred(): void
    {
        $scan = $this->scanWithSeverities(array_fill(0, 10, Finding::SEVERITY_CRITICAL)); // 10 * 25 = 250

        $scan->computeScore();

        $this->assertSame(0, $scan->getScore());
        $this->assertSame(Scan::GRADE_F, $scan->getGrade());
    }

    public function testUnknownSeverityContributesNoPenalty(): void
    {
        $scan = $this->scanWithSeverities(['unknown-severity']);

        $scan->computeScore();

        $this->assertSame(100, $scan->getScore());
        $this->assertSame(Scan::GRADE_A, $scan->getGrade());
    }

    public function testFinishSetsStatusDoneAndComputesScore(): void
    {
        $scan = $this->scanWithSeverities([Finding::SEVERITY_CRITICAL]);

        $scan->finish();

        $this->assertSame(Scan::STATUS_DONE, $scan->getStatus());
        $this->assertNotNull($scan->getFinishedAt());
        $this->assertSame(75, $scan->getScore());
        $this->assertSame(Scan::GRADE_B, $scan->getGrade());
    }

    /**
     * @param string[] $severities
     */
    private function scanWithSeverities(array $severities): Scan
    {
        $scan = new Scan();
        foreach ($severities as $severity) {
            $finding = new Finding();
            $finding
                ->setTool('securescan')
                ->setSeverity($severity)
                ->setOwaspCategory(Finding::OWASP_A01)
                ->setTitle('Test finding');
            $scan->addFinding($finding);
        }

        return $scan;
    }
}