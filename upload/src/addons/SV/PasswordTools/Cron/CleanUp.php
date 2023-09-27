<?php

namespace SV\PasswordTools\Cron;

use SV\PasswordTools\Job\PasswordCleanup;

class CleanUp
{
    public static function runDailyCleanUp()
    {
        \XF::app()->jobManager()->enqueueLater('pruneSvPasswordHashCache', \XF::$time + 1, PasswordCleanup::class, []);
    }
}