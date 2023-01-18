<?php
/**
 * @noinspection PhpMissingReturnTypeInspection
 */

namespace SV\PasswordTools\XF\Service\User;

use SV\PasswordTools\XF\Entity\UserAuth;
use function strlen;

/**
 * Extends \XF\Service\User\Login
 */
class Login extends XFCP_Login
{
    public function validate($password, &$error = null)
    {
        $user = parent::validate($password, $error);
        if (strlen($password) !== 0 && $user !== null)
        {
            /** @var UserAuth $auth */
            $auth = $user->Auth;
            $options = \XF::options();
            $checkPwnedPassword = (bool)($options->svAlertOnCompromisedPasswordOnLogin ?? true);
            if ($auth === null || !$checkPwnedPassword)
            {
                return $user;
            }
            // If $lastPwnedPasswordCheck is non-empty, this implies the last compromised password check failed
            // The value will be reset to null on the next password change, allowing 2fa to be forced if configured without additional compromised password checks
            $lastPwnedPasswordCheck = $auth->sv_pwned_password_check ?? 0;
            $recurring = (int)($options->svPwnedPasswordAlertRecurring ?? 86400);
            if ($lastPwnedPasswordCheck + $recurring < \XF::$time)
            {
                // the pwned password check needs to run after the password validation, but before the 2fa check
                // otherwise the 'Force email two factor authentication on compromised password' option will not reliably trigger
                try
                {
                    $useCount = 0;
                    if ($auth->isPwnedPassword($password, $useCount, false))
                    {
                        $auth->flagPwnedPasswordCheck();
                        $auth->svNagOnWeakPassword($useCount);
                    }
                }
                catch (\Throwable $e)
                {
                    \XF::logException($e);
                }
            }
        }

        return $user;
    }
}