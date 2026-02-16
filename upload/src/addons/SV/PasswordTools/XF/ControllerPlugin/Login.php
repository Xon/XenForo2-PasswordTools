<?php

namespace SV\PasswordTools\XF\ControllerPlugin;

use SV\StandardLib\Helper;
use XF\Repository\UserTfaTrusted as UserTfaTrustedRepository;
use function random_int;

/**
 * @extends \XF\ControllerPlugin\Login
 */
class Login extends XFCP_Login
{
    /**
     * @param int $userId
     * @return string
     * @noinspection PhpMissingReturnTypeInspection
     * @noinspection PhpDocMissingThrowsInspection
     */
    public function setDeviceTrusted($userId)
    {
        // default duration is 30 days, and the cookie expiring after 45 days
        $duration = \XF::options()->sv2faExpiryTime ?? 90;
        if ($duration <= 0)
        {
            return parent::setDeviceTrusted($userId);
        }

        // This allows that to be vastly expanded and defaults to 90 days between prompts,
        // then 120s before the cookie expires
        $trustedUntil = \XF::$time + 86400 * $duration;
        $cookieLifeTime = 86400 * ($duration + 30);

        // jitter expiring similar to UserTfaTrusted::_preSave()
        $offsetJitter = random_int(0, 4 * 24) * 3600;
        $trustedUntil += $offsetJitter;
        $cookieLifeTime += $offsetJitter;

        $tfaTrustRepo = Helper::repository(UserTfaTrustedRepository::class);
        $key = $tfaTrustRepo->createTrustedKey($userId, $trustedUntil);

        \XF::app()->response()->setCookie('tfa_trust', $key, $cookieLifeTime, null, true);

        return $key;
    }
}