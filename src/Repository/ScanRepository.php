<?php

namespace App\Repository;

use App\Entity\Scan;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @extends ServiceEntityRepository<Scan>
 */
class ScanRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Scan::class);
    }
    public function findByUser(UserInterface $user): array
    {
        return $this->createQueryBuilder('s')
            ->distinct()
            ->join('s.project', 'p')
            ->where('p.owner = :user')
            ->setParameter('user', $user)
            ->orderBy('s.startedAt', 'DESC')
            ->getQuery()
            ->getResult();
    }
}
