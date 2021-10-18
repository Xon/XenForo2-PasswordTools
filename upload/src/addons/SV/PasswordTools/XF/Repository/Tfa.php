<?php

namespace SV\PasswordTools\XF\Repository;

use SV\PasswordTools\Globals;
use SV\PasswordTools\XF\Entity\UserAuth;
use XF\Entity\User;

/**
 * Extends \XF\Repository\Tfa
 */
class Tfa extends XFCP_Tfa
{
    public function isSvForcedEmail2fa(\XF\Entity\User $user) : bool
    {
        if (!\XF::config('enableTfa'))
        {
            return false;
        }

        /** @var UserAuth $auth */
        $auth = $user->Auth;
        if (!$auth || !$user->Option)
        {
            // damaged account configuration
            return false;
        }

        if ($user->Option->use_tfa)
        {
            return false;
        }

        $pwnedPasswordCheck = $auth->sv_pwned_password_check ?? 0;
        if ($pwnedPasswordCheck === 0)
        {
            return false;
        }

        /** @var \XF\Entity\TfaProvider $email2FaProvider */
        $email2FaProvider = $this->app()->find('XF:TfaProvider', 'email');
        $handler = $email2FaProvider->handler ?? null;
        if ($handler === null || $handler->requiresConfig() || !$handler->canEnable())
        {
            if (\XF::$debugMode)
            {
                \XF::logError('email 2fa provider appears damage or extended by an incompatible add-ons.');
            }

            return false;
        }

        if (!$handler->meetsRequirements($user, $error))
        {
            // user doesn't have email or the email is broken
            return false;
        }

        return true;
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public function isUserTfaConfirmationRequired(\XF\Entity\User $user, $trustKey = null)
    {
        $isRequired = parent::isUserTfaConfirmationRequired($user, $trustKey);
        if ($isRequired)
        {
            return true;
        }

        if ($this->isSvForcedEmail2fa($user))
        {
            // user has a compromised password, force 2fa. login/two-step forces email 2fa enabled
            return true;
        }

        return false;
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public function getAvailableProvidersForUser($userId)
    {
        /** @var User $user */
        $user = $this->app()->find('XF:User', $userId);

        Globals::$forceEmail2FA = $user !== null && $this->isSvForcedEmail2fa($user);
        try
        {
            return parent::getAvailableProvidersForUser($userId);
        }
        finally
        {
            Globals::$forceEmail2FA = false;
        }
    }

    /**
     * @param User                   $user
     * @param \XF\Entity\TfaProvider $provider
     * @param array                  $config
     * @param bool                   $updateLastUsed
     * @return bool
     * @throws \XF\PrintableException
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function updateUserTfaData(\XF\Entity\User $user, \XF\Entity\TfaProvider $provider, array $config, $updateLastUsed = true)
    {
        $result = parent::updateUserTfaData($user, $provider, $config, $updateLastUsed);
        if ($result || $provider->provider_id !== 'email' || !$this->isSvForcedEmail2fa($user))
        {
            return true;
        }

        // prevent the use_tfa flag being set
        $option = $user->Option;
        $user->hydrateRelation('Option', null);
        try
        {
            // ensure the email 2fa code is written to the database

            /** @var \XF\Entity\UserTfa $userTfa */
            $userTfa = $this->em->create('XF:UserTfa');
            $userTfa->user_id = $user->user_id;
            $userTfa->provider_id = $provider->provider_id;
            $userTfa->provider_data = $config;
            $userTfa->last_used_date = \XF::$time;
            $userTfa->save();
        }
        finally
        {
            $user->hydrateRelation('Option', $option);
        }

        return true;
    }
}