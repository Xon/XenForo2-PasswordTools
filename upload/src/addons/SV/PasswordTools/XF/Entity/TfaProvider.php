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

        if ($this->provider_id === 'email')
        {
            if (Globals::$forceEmail2FA ?? false)
            {
                $enabled = true;
            }
            else
            {
                $config = $this->getUserProviderConfig($userId);
                if ($config['np_enabled_as_fallback'] ?? false)
                {
                    $enabled = false;
                }
            }
        }

        return $enabled;
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