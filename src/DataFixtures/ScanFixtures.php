<?php

namespace App\DataFixtures;

use App\Entity\Project;
use App\Entity\Scan;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;
use Doctrine\Persistence\ObjectManager;

class ScanFixtures extends Fixture implements FixtureGroupInterface
{
    public const SCAN_PHP_REF = 'scan-php';
    public const SCAN_JS_REF  = 'scan-js';
    public const SCAN_PY_REF  = 'scan-py';

    public static function getGroups(): array
    {
        return ['scans'];
    }

    public function load(ObjectManager $manager): void
    {
        $projectRepo = $manager->getRepository(Project::class);

        $projects = [
            self::SCAN_PHP_REF => $projectRepo->findOneBy(['name' => 'API Backend']),
            self::SCAN_JS_REF  => $projectRepo->findOneBy(['name' => 'Frontend App']),
            self::SCAN_PY_REF  => $projectRepo->findOneBy(['name' => 'Data Pipeline']),
        ];

        foreach ($projects as $ref => $project) {
            if (!$project) {
                throw new \RuntimeException('Projet introuvable pour : ' . $ref);
            }

            $scan = new Scan();
            $scan->setProject($project);
            $manager->persist($scan);
        }

        $manager->flush();
    }
}
