<?php

namespace SV\PasswordTools\XF\Service\User;

use SV\PasswordTools\XF\Entity\UserAuth;

/**
 * Extends \XF\Service\User\Login
 */
class Login extends XFCP_Login
{
    public function validate($password, &$error = null)
    {
        $user = parent::validate($password, $error);
        if (\strlen($password) !== 0 && $user && $user->Auth)
        {
            \XF::runLater(function () use ($user, $password) {
                try
                {
                    $useCount = 0;
                    /** @var UserAuth $auth */
                    $auth = $user->Auth;
                    if ($auth->isPwnedPassword($password, $useCount, false))
                    {

                        /** @var \XF\Repository\UserAlert $alertRepo */
                        $alertRepo = $this->repository('XF:UserAlert');
                        $alertRepo->alert(
                            $user,
                            0, '',
                            'user', $user->user_id,
                            "pwned_password", [
                                'depends_on_addon_id' => 'SV/PasswordTools', // XF2.1 compatible
                                'count'          => $useCount,
                                'countFormatted' => \XF::language()->numberFormat($useCount),
                            ]
                        );
                    }
                }
                catch(\Throwable $e)
                {
                    \XF::logException($e);
                }
            });
        }

        return $user;
    }
}