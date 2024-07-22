<?php
/**
 * @noinspection PhpMissingReturnTypeInspection
 */

namespace SV\PasswordTools\XF\Service\User;

use SV\PasswordTools\XF\Entity\UserAuth;
use SV\StandardLib\Helper;
use XF\Service\User\PasswordReset as PasswordResetService;
use XF\Service\User\UserGroupChange as UserGroupChangeService;
use function strlen;

/**
 * @extends \XF\Service\User\Login
 */
class Login extends XFCP_Login
{
    public function validate($password, &$error = null)
    {
        $user = parent::validate($password, $error);
        if (strlen($password) === 0 || $user === null)
        {
            return $user;
        }

        /** @var UserAuth $auth */
        $auth = $user->Auth;
        if ($auth === null)
        {
            return $user;
        }

        $options = \XF::options();
        $alertOnCompromisedPassword = (bool)($options->svAlertOnCompromisedPasswordOnLogin ?? true);
        $forcePasswordResetOnCompromisedPassword = (bool)($options->svPwnedPasswordForcePasswordReset ?? false);
        $pwnedPasswordGroupId = (int)($options->svPwnedPasswordGroup ?? 0);
        $forceEmail2fa = $auth->svIsForceEmail2Fa();
        // If sv_pwned_password_check is non-empty, this implies the last compromised password check failed
        // The value will be reset to null on the next password change, allowing 2fa to be forced if configured without additional compromised password checks
        $lastPwnedPasswordCheck = $auth->sv_pwned_password_check ?? 0;
        $recurring = (int)($options->svPwnedPasswordAlertRecurring ?? 24) * 60*60;
        $sendCompromisedPasswordAlert = $alertOnCompromisedPassword && ($lastPwnedPasswordCheck + $recurring < \XF::$time);

        // Only do pwnedpassword checks if required
        if (!$sendCompromisedPasswordAlert && !$forcePasswordResetOnCompromisedPassword && !$forceEmail2fa && $pwnedPasswordGroupId === 0)
        {
            return $user;
        }

        // the pwned password check needs to run after the password validation, but before the 2fa check
        // otherwise the 'Force email two-factor authentication on compromised password' option will not reliably trigger
        try
        {
            $useCount = 0;
            if ($auth->isPwnedPassword($password, $useCount, false))
            {
                $db = \XF::db();
                $db->beginTransaction();

                $auth->flagPwnedPasswordCheck();
                if ($pwnedPasswordGroupId !== 0 && !$user->isMemberOf($pwnedPasswordGroupId))
                {
                    $userGroupChangeService = Helper::service(UserGroupChangeService::class);
                    $userGroupChangeService->addUserGroupChange($user->user_id, 'svCompromisedPassword', $pwnedPasswordGroupId);
                }

                $passwordReset = null;
                if ($forcePasswordResetOnCompromisedPassword)
                {
                    if (\XF::$versionId > 2020000)
                    {
                        if ($user->security_lock === '')
                        {
                            $user->security_lock = 'reset';
                            $user->save();
                        }
                    }
                    else
                    {
                        // prevent the security reset from happening again
                        $auth->resetPassword();
                        $auth->save();

                        $passwordReset = Helper::service(PasswordResetService::class, $user);
                        $passwordReset->setAdminReset(true);

                        // prevent login
                        $user = null;
                        $error = \XF::phrase('svPasswordTools_compromised_password_forced_reset');
                    }
                }

                $db->commit();

                // XF2.1 support
                if ($passwordReset !== null)
                {
                    $passwordReset->triggerConfirmation();
                }

                if ($sendCompromisedPasswordAlert)
                {
                    $auth->svNagOnWeakPassword($useCount);
                }
            }
        }
        catch (\Throwable $e)
        {
            \XF::logException($e);
        }

        return $user;
    }
}