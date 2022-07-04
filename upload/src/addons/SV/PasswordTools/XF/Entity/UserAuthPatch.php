<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * Class UserAuth
 * Extends \XF\Entity\UserAuth
 *
 * @package SV\PasswordTools\XF\Entity
 */
class UserAuthPatch extends XFCP_UserAuthPatch
{
    public function resetPassword()
    {
        $this->setOption('svAutomatedEdit', true);
        try
        {
            return parent::resetPassword();
        }
        finally
        {
            $this->resetOption('svAutomatedEdit');
        }
    }
}