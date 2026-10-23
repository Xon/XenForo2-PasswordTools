<?php

namespace SV\PasswordTools\Cron;

use SV\PasswordTools\Job\PasswordCleanup;

class CleanUp
{
    public static function runDailyCleanUp()
    {
        PasswordCleanup::enqueue();
    }
}