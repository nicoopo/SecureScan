<?php

namespace App\Security\Voter;

use App\Entity\Project;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;

/**
 * Garantit qu'un utilisateur ne peut accéder qu'à ses propres projets.
 *
 * Usage dans un controller :
 *   $this->denyAccessUnlessGranted(ProjectVoter::VIEW, $project);
 *   $this->denyAccessUnlessGranted(ProjectVoter::EDIT, $project);
 */
class ProjectVoter extends Voter
{
    public const VIEW   = 'project_view';
    public const EDIT   = 'project_edit';
    public const DELETE = 'project_delete';
    public const SCAN   = 'project_scan';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof Project
            && in_array($attribute, [self::VIEW, self::EDIT, self::DELETE, self::SCAN], true);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote = null): bool
    {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false; // non authentifié
        }

        /** @var Project $project */
        $project = $subject;

        // Seul le propriétaire a accès
        return $project->getOwner() === $user;
    }
}
