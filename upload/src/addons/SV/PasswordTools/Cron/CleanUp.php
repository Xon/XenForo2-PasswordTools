<?php

namespace SV\PasswordTools\Cron;

class CleanUp
{
    public static function runDailyCleanUp()
    {
        \XF::app()->jobManager()->enqueueLater('pruneSvPasswordHashCache', \XF::$time + 1, 'SV\PasswordTools:PasswordCleanup', []);
    }
}