<?php

namespace App\Tests\Security\Voter;

use App\Entity\Project;
use App\Entity\User;
use App\Security\Voter\ProjectVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class ProjectVoterTest extends TestCase
{
    private ProjectVoter $voter;

    protected function setUp(): void
    {
        $this->voter = new ProjectVoter();
    }

    private function tokenFor(?object $user): TokenInterface
    {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn($user);

        return $token;
    }

    public function testOwnerIsGrantedOnAllAttributes(): void
    {
        $owner = new User();
        $project = (new Project())->setOwner($owner);

        foreach ([ProjectVoter::VIEW, ProjectVoter::EDIT, ProjectVoter::DELETE, ProjectVoter::SCAN] as $attribute) {
            $result = $this->voter->vote($this->tokenFor($owner), $project, [$attribute]);
            $this->assertSame(VoterInterface::ACCESS_GRANTED, $result, "Attribute {$attribute} should be granted to the owner");
        }
    }

    public function testOtherUserIsDeniedOnAllAttributes(): void
    {
        $owner = new User();
        $otherUser = new User();
        $project = (new Project())->setOwner($owner);

        foreach ([ProjectVoter::VIEW, ProjectVoter::EDIT, ProjectVoter::DELETE, ProjectVoter::SCAN] as $attribute) {
            $result = $this->voter->vote($this->tokenFor($otherUser), $project, [$attribute]);
            $this->assertSame(VoterInterface::ACCESS_DENIED, $result, "Attribute {$attribute} should be denied to a non-owner");
        }
    }

    public function testUnauthenticatedTokenIsDenied(): void
    {
        // getUser() renvoie null pour un token non authentifié (ex. anonyme).
        $project = (new Project())->setOwner(new User());

        $result = $this->voter->vote($this->tokenFor(null), $project, [ProjectVoter::VIEW]);

        $this->assertSame(VoterInterface::ACCESS_DENIED, $result);
    }

    public function testNonAppUserTokenSubjectIsDenied(): void
    {
        // Défense en profondeur : même si getUser() renvoie un UserInterface valide
        // mais qui n'est pas une App\Entity\User (ex. autre provider d'authentification).
        $foreignUser = $this->createStub(UserInterface::class);
        $project = (new Project())->setOwner(new User());

        $result = $this->voter->vote($this->tokenFor($foreignUser), $project, [ProjectVoter::VIEW]);

        $this->assertSame(VoterInterface::ACCESS_DENIED, $result);
    }

    public function testAbstainsOnUnsupportedSubject(): void
    {
        $result = $this->voter->vote($this->tokenFor(new User()), new \stdClass(), [ProjectVoter::VIEW]);

        $this->assertSame(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    public function testAbstainsOnUnsupportedAttribute(): void
    {
        $owner = new User();
        $project = (new Project())->setOwner($owner);

        $result = $this->voter->vote($this->tokenFor($owner), $project, ['project_unknown']);

        $this->assertSame(VoterInterface::ACCESS_ABSTAIN, $result);
    }
}