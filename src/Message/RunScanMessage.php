<?php

namespace App\Message;

final class RunScanMessage
{
    public function __construct(
        private readonly int $scanId,
    ) {}

    public function getScanId(): int
    {
        return $this->scanId;
    }
}