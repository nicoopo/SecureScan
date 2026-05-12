<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;

class UserFixtures extends Fixture implements FixtureGroupInterface
{
    public const USER_DEMO_REF = 'user-demo';

    public function __construct(
        private UserPasswordHasherInterface $hasher,
    ) {}
    public static function getGroups(): array
    {
        return ['users'];
    }

    public function load(ObjectManager $manager): void
    {
        $user = new User();
        $user->setEmail('demo@securescan.fr');
        $user->setFullName('Demo User');
        $user->setPassword($this->hasher->hashPassword($user, 'password'));
        $user->setIsVerified(true);
        $user->setGitUsername('demo-user');
        $manager->persist($user);
        $manager->flush();

        $this->addReference(self::USER_DEMO_REF, $user);
    }
}
