<?php

namespace SV\PasswordTools\Job;

use XF\Job\AbstractJob;
use XF\Job\JobResult;
use function max;

class PasswordCleanup extends AbstractJob
{
    protected $defaultData = [
        'cutOff' => null,
        'batch'  => 50000,
    ];

    public static function enqueue(?int $cutOff = null): void
    {
        if ($cutOff === null)
        {
            $cutOff = \XF::$time - max(0, \XF::options()->svPwnedPasswordCacheTime ?? 7) * 86400;
        }

        \XF::app()->jobManager()->enqueueLater('pruneSvPasswordHashCache', \XF::$time + 1, PasswordCleanup::class, [
            'cutOff' => $cutOff,
            'batch' => 10000,
        ]);
    }

    /**
     * @param float|int $maxRunTime
     */
    public function run($maxRunTime): JobResult
    {
        $cutoff = $this->data['cutoff'] ?? 0;
        $batchSize = $this->data['batch'] ?? 0;
        if ($cutoff <= 0 || $batchSize <= 0)
        {
            return $this->complete();
        }

        $db = \XF::db();
        $statement = $db->query($db->limit('
            DELETE
            FROM xf_sv_pwned_hash_cache
            WHERE last_update < ?
        ', $batchSize), $cutoff);

        if ($statement->rowsAffected() < $batchSize)
        {
            return $this->complete();
        }

        return $this->resume();
    }
    /**
     * @deprecated
     */
    protected function doCleanup(int $cutOff)
    {
    }

    public function getStatusMessage(): string
    {
        return '';
    }

    public function canCancel(): bool
    {
        return false;
    }

    public function canTriggerByChoice(): bool
    {
        return false;
    }
}