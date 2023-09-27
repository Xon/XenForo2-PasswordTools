<?php

namespace SV\PasswordTools\Job;

use XF\Job\AbstractJob;
use XF\Job\JobResult;

class PasswordCleanup extends AbstractJob
{
    public function run($maxRunTime): JobResult
    {
        $pwnedPasswordCacheTime = (int)(\XF::options()->svPwnedPasswordCacheTime ?? 7);
        $this->doCleanup($pwnedPasswordCacheTime);

        return $this->complete();
    }

    protected function doCleanup(int $days = 0)
    {
        if ($days <= 0)
        {
            return;
        }
        $cutoff = \XF::$time - $days * 86400;

        \XF::db()->query('DELETE FROM xf_sv_pwned_hash_cache WHERE last_update < ?', $cutoff);
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