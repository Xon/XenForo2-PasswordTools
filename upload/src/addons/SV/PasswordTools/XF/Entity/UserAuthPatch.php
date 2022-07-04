<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * Class UserAuth
 * Extends \XF\Entity\UserAuth
 *
 * @package SV\PasswordTools\XF\Entity
 */
class UserAuthPatch extends XFCP_UserAuth
{
    public function resetPassword()
    {
        $this->setOption('svAdminEdit', true);
        try
        {
            return parent::resetPassword();
        }
        finally
        {
            $this->resetOption('svAdminEdit');
        }
    }
}