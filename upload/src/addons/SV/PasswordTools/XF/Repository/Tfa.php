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

        if ($user->Option->use_tfa)
        {
            Globals::$forceEmail2FA = true;
            try
            {
                $providers = parent::getAvailableProvidersForUser($user->user_id);
                unset($providers['backup']);
            }
            finally
            {
                Globals::$forceEmail2FA = false;
            }

            /** @var \XF\Entity\TfaProvider $email */
            $email = $providers['email'] ?? null;
            if ($email !== null)
            {
                $config = $email->getUserProviderConfig($user->user_id);
                if ($config['np_enabled_as_fallback'] ?? false)
                {
                    return true;
                }
            }

            if (\count($providers) === 0)
            {
                // If a user has use_tfa = true and providers = ['backup'], a state that XF considers to be valid but treats the same as use_tfa = false
                // Force an entry into xf_user_tfa, so the email 2fa is enabled and can store its code
                $this->addEmail2faRecord($user, []);

                return true;
            }

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

        /** @var \XF\Repository\UserTfaTrusted $tfaTrustRepo */
        $tfaTrustRepo = $this->repository('XF:UserTfaTrusted');
        if ($trustKey && $tfaTrustRepo->getTfaTrustRecord($user->user_id, $trustKey))
        {
            return false;
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
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function updateUserTfaData(\XF\Entity\User $user, \XF\Entity\TfaProvider $provider, array $config, $updateLastUsed = true)
    {
        $result = parent::updateUserTfaData($user, $provider, $config, $updateLastUsed);
        if ($result || $provider->provider_id !== 'email' || !$this->isSvForcedEmail2fa($user))
        {
            return true;
        }
        // ensure the email 2fa code is written to the database

        $this->addEmail2faRecord($user, $config);

        return true;
    }

    protected function addEmail2faRecord(\XF\Entity\User $user, array $config): \XF\Entity\UserTfa
    {
        /** @var \XF\Entity\UserTfa $userTfa */
        $userTfa = $this->em->create('XF:UserTfa');

        // signal this is a tainted email provider until it gets enabled explicitly
        $config['np_enabled_as_fallback'] = true;

        $userTfa->user_id = $user->user_id;
        $userTfa->provider_id = 'email';
        $userTfa->provider_data = $config;
        $userTfa->last_used_date = \XF::$time;
        // prevent the use_tfa flag being set
        $userTfa->hydrateRelation('User', null);

        $userTfa->save();
        // probably not needed
        $userTfa->hydrateRelation('User', $user);

        return $userTfa;
    }

    /**
     * @param User                   $user
     * @param \XF\Entity\TfaProvider $provider
     * @param array                  $config
     * @param false                  $backupAdded
     * @return \XF\Mvc\Entity\Entity|null
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function enableUserTfaProvider(\XF\Entity\User $user, \XF\Entity\TfaProvider $provider, array $config, &$backupAdded = false)
    {
        $db = $this->db();
        $db->beginTransaction();

        if ($config['np_enabled_as_fallback'] ?? true)
        {
            unset($config['np_enabled_as_fallback']);
            // delete via raw query to avoid tfa cleanup
            $db->query('delete from xf_user_tfa where user_id = ? and provider_id = ?', [$user->user_id, $provider->provider_id]);
        }

        try
        {
            return parent::enableUserTfaProvider($user, $provider, $config,$backupAdded);
        }
        finally
        {
            $db->commit();
        }
    }
}