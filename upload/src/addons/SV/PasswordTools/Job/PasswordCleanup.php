<?php

namespace SV\PasswordTools\Job;

use XF\Job\AbstractJob;

class PasswordCleanup extends AbstractJob
{
    public function run($maxRunTime): \XF\Job\JobResult
    {
        $pwnedPasswordCacheTime = (int)\XF::options()->svPwnedPasswordCacheTime;
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