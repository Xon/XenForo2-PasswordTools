<?php

namespace SV\PasswordTools\XF\Repository;

use SV\PasswordTools\Globals;
use SV\PasswordTools\XF\Entity\UserAuth;
use SV\StandardLib\Helper;
use XF\Db\DuplicateKeyException;
use XF\Db\Exception as DbException;
use XF\Entity\TfaProvider as TfaProviderEntity;
use XF\Entity\User as UserEntity;
use XF\Entity\UserTfa as UserTfaEntity;
use XF\Mvc\Entity\Entity;
use XF\Repository\UserTfaTrusted as UserTfaTrustedRepo;
use function count;

/**
 * Extends \XF\Repository\Tfa
 */
class Tfa extends XFCP_Tfa
{
    public function isSvForcedEmail2fa(UserEntity $user, ?string $trustKey = null): bool
    {
        /** @var UserAuth $auth */
        $auth = $user->Auth;
        if ($auth === null || $user->Option === null)
        {
            // damaged account configuration
            return false;
        }

        if (!$auth->svIsForceEmail2Fa())
        {
            return false;
        }

        if (!$auth->hasPwnedPassword())
        {
            return false;
        }

        $tfaTrustRepo = Helper::repository(UserTfaTrustedRepo::class);
        if ($trustKey && $tfaTrustRepo->getTfaTrustRecord($user->user_id, $trustKey))
        {
            return false;
        }

        /** @var TfaProviderEntity $email2FaProvider */
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

            /** @var TfaProviderEntity $email */
            $email = $providers['email'] ?? null;
            if ($email !== null)
            {
                $config = $email->getUserProviderConfig($user->user_id);
                if ($config['np_enabled_as_fallback'] ?? false)
                {
                    return true;
                }
            }

            if (count($providers) === 0)
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
    public function isUserTfaConfirmationRequired(UserEntity $user, $trustKey = null)
    {
        $isRequired = parent::isUserTfaConfirmationRequired($user, $trustKey);
        if ($isRequired)
        {
            return true;
        }

        if ($this->isSvForcedEmail2fa($user, $trustKey))
        {
            // user has a compromised password, force 2fa. login/two-step forces email 2fa enabled
            return true;
        }

        return false;
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public function getAvailableProvidersForUser($userId)
    {
        /** @var UserEntity $user */
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
     * @param UserEntity        $user
     * @param TfaProviderEntity $provider
     * @param array             $config
     * @param bool              $updateLastUsed
     * @return bool
     * @noinspection PhpMissingReturnTypeInspection
     * @throws DuplicateKeyException
     */
    public function updateUserTfaData(UserEntity $user, TfaProviderEntity $provider, array $config, $updateLastUsed = true)
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

    protected function addEmail2faRecord(UserEntity $user, array $config): UserTfaEntity
    {
        /** @var UserTfaEntity $userTfa */
        $userTfa = $this->em->create('XF:UserTfa');

        // signal this is a tainted email provider until it gets enabled explicitly
        $config['np_enabled_as_fallback'] = true;

        $userTfa->user_id = $user->user_id;
        $userTfa->provider_id = 'email';
        $userTfa->provider_data = $config;
        $userTfa->last_used_date = \XF::$time;
        // prevent the use_tfa flag being set
        $userTfa->hydrateRelation('User', null);

        try
        {
            $userTfa->save();
        }
            /** @noinspection PhpRedundantCatchClauseInspection */
        catch (DuplicateKeyException $e)
        {
            if ($this->db()->inTransaction())
            {
                throw $e;
            }
            $userTfa = $this->app()
                            ->finder('XF:UserTfa')
                            ->where('user_id', $user->user_id)
                            ->where('provider_id', 'email')
                            ->fetchOne();
        }

        // probably not needed
        $userTfa->hydrateRelation('User', $user);

        return $userTfa;
    }

    /**
     * @param UserEntity        $user
     * @param TfaProviderEntity $provider
     * @param array             $config
     * @param false             $backupAdded
     * @return Entity|null
     * @throws DbException
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function enableUserTfaProvider(UserEntity $user, TfaProviderEntity $provider, array $config, &$backupAdded = false)
    {
        $db = \XF::db();
        $db->beginTransaction();

        if ($config['np_enabled_as_fallback'] ?? true)
        {
            unset($config['np_enabled_as_fallback']);
            // delete via raw query to avoid tfa cleanup
            $db->query('DELETE FROM xf_user_tfa WHERE user_id = ? AND provider_id = ?', [$user->user_id, $provider->provider_id]);
        }

        try
        {
            return parent::enableUserTfaProvider($user, $provider, $config, $backupAdded);
        }
        finally
        {
            $db->commit();
        }
    }
}