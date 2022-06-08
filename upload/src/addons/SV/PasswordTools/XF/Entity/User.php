<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * Class User
 * Extends \XF\Entity\User
 *
 * @package SV\PasswordTools\XF\Entity
 * @property UserAuth|null Auth
 */
class User extends XFCP_User
{
    public function setOption($name, $value)
    {
        parent::setOption($name,$value);

        if ($name === 'admin_edit' && $this->Auth !== null)
        {
            $this->Auth->setOption('svAdminEdit', $value);
        }
    }

    public function resetOption($name)
    {
        parent::resetOption($name);

        if ($name === 'admin_edit' && $this->Auth !== null)
        {
            $this->Auth->resetOption('svAdminEdit');
        }
    }
}