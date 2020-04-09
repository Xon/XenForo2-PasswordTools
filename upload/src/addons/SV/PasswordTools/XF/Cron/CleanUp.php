<?php

namespace SV\PasswordTools\XF\Cron;

class CleanUp extends XFCP_CleanUp
{
    public static function runDailyCleanUp()
    {
        \xF::app()->jobManager()->enqueueLater('pruneSvPasswordHashCache', \XF::$time + 1, 'SVPasswordTools:PasswordCleanup', [], false);

        parent::runDailyCleanUp();
    }
}