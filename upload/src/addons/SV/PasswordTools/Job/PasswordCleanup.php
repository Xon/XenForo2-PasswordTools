<?php

namespace SV\PasswordTools\Job;

use XF\Job\AbstractJob;

class PasswordCleanup extends AbstractJob
{

    /**
     * @inheritDoc
     */
    public function run($maxRunTime)
    {
        $pwnedPasswordCacheTime = (int)\XF::options()->svPwnedPasswordCacheTime;
        $this->doCleanup($pwnedPasswordCacheTime);

        return $this->complete();
    }

    /**
     * @param int $days
     * @throws \XF\Db\Exception
     */
    protected function doCleanup($days = 0)
    {
        if ($days <= 0)
        {
            return;
        }
        $cutoff = \XF::$time - $days * 86400;

        \XF::db()->query('DELETE FROM xf_sv_pwned_hash_cache WHERE last_update < ?', $cutoff);
    }

    public function getStatusMessage()
    {
        return '';
    }

    public function canCancel()
    {
        return false;
    }

    public function canTriggerByChoice()
    {
        return false;
    }


}