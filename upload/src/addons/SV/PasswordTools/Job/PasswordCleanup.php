<?php

namespace SV\PasswordTools\Job;

use XF\Job\AbstractJob;
use XF\Job\JobResult;
use function max;
use function microtime;

class PasswordCleanup extends AbstractJob
{
    public const MAX_BATCH_SIZE = 50000;
    public const INITIAL_BATCH_SIZE = 1000;

    protected $defaultData = [
        'cutOff' => null,
        'steps' => 0,
        'start' => 0,
        'batch' => self::INITIAL_BATCH_SIZE,
    ];

    public static function enqueue(?int $cutOff = null): void
    {
        if ($cutOff === null)
        {
            $cutOff = \XF::$time - max(0, \XF::options()->svPwnedPasswordCacheTime ?? 7) * 86400;
        }

        \XF::app()->jobManager()->enqueueLater('pruneSvPasswordHashCache', \XF::$time + 1, PasswordCleanup::class, [
            'cutOff' => $cutOff,
            'batch' => self::INITIAL_BATCH_SIZE,
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

        $start = microtime(true);

        $this->data['steps']++;

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
        $done = $statement->rowsAffected();

        $this->data['batch'] = $this->calculateOptimalBatch($this->data['batch'], $done, $start, $maxRunTime, self::MAX_BATCH_SIZE);

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