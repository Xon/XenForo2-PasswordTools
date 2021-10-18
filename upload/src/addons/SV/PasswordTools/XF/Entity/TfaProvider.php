<?php
/**
 * @noinspection PhpMissingReturnTypeInspection
 */

namespace SV\PasswordTools\XF\Entity;

use SV\PasswordTools\Globals;

/**
 * Extends \XF\Entity\TfaProvider
 */
class TfaProvider extends XFCP_TfaProvider
{
    /**
     * @param int|null $userId
     * @return bool
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

    public function canEnable($userId = null)
    {
        $canEnable = parent::canEnable($userId);
        if (!$canEnable && $this->provider_id === 'email')
        {
            $config = $this->getUserProviderConfig($userId);
            if ($config['np_enabled_as_fallback'] ?? false)
            {
                $canEnable = true;
            }
        }

        return $canEnable;
    }

    public function canDisable($userId = null)
    {
        $canDisable = parent::canDisable($userId);
        if ($canDisable && $this->provider_id === 'email')
        {
            $config = $this->getUserProviderConfig($userId);
            if ($config['np_enabled_as_fallback'] ?? false)
            {
                $canDisable = false;
            }
        }

        return $canDisable;
    }

    /**
     * @param int|null $userId
     * @return array|null
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