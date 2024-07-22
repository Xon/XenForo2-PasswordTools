<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * @extends \XF\Entity\UserAuth
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