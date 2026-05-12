<?php

namespace App\DataFixtures;

use App\Entity\Project;
use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Common\DataFixtures\DependencyInterface;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;

class ProjectFixtures extends Fixture implements FixtureGroupInterface
{
    public const PROJECT_PHP_REF  = 'project-php';
    public const PROJECT_JS_REF   = 'project-js';
    public const PROJECT_PY_REF   = 'project-py';

    public static function getGroups(): array
    {
        return ['projects'];
    }

    public function load(ObjectManager $manager): void
    {
        $user = $manager->getRepository(User::class)->findOneBy(['email' => 'demo@securescan.fr']);
        if (!$user) {
            throw new \RuntimeException('Lance d\'abord UserFixtures !');
        }

        $projects = [
            [
                'ref'      => self::PROJECT_PHP_REF,
                'name'     => 'API Backend',
                'url'      => 'https://github.com/acme/api-backend',
                'language' => Project::LANGUAGE_PHP,
            ],
            [
                'ref'      => self::PROJECT_JS_REF,
                'name'     => 'Frontend App',
                'url'      => 'https://github.com/acme/frontend-app',
                'language' => Project::LANGUAGE_JAVASCRIPT,
            ],
            [
                'ref'      => self::PROJECT_PY_REF,
                'name'     => 'Data Pipeline',
                'url'      => 'https://github.com/acme/data-pipeline',
                'language' => Project::LANGUAGE_PYTHON,
            ],
        ];

        foreach ($projects as $data) {
            $project = new Project();
            $project->setOwner($user);
            $project->setName($data['name']);
            $project->setRepositoryUrl($data['url']);
            $project->setSource(Project::SOURCE_GIT);
            $project->setLanguage($data['language']);
            $manager->persist($project);

            $this->addReference($data['ref'], $project);
        }

        $manager->flush();
    }

    public function getDependencies(): array
    {
        return [];
    }
}
