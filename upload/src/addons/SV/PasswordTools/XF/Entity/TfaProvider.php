<?php

namespace SV\PasswordTools\XF\Entity;

use SV\PasswordTools\Globals;
use XF\Mvc\Entity\Entity;
use XF\Mvc\Entity\Structure;

/**
 * Extends \XF\Entity\TfaProvider
 */
class TfaProvider extends XFCP_TfaProvider
{
    /**
     * @param int|null $userId
     * @return bool
     *
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function isEnabled($userId = null)
    {
        $enabled = parent::isEnabled($userId);
        if ($enabled)
        {
            return true;
        }

        if ((Globals::$forceEmail2FA ?? false) && $this->provider_id === 'email')
        {
            return true;
        }

        return false;
    }

    /**
     * @param int|null $userId
     * @return array|null
     *
     * @noinspection PhpMissingReturnTypeInspection
     */
    public function getUserProviderConfig($userId = null)
    {
        $data = parent::getUserProviderConfig($userId);

        if ($data === null && $this->provider_id === 'email')
        {
            return [];
        }

        return $data;
    }
}