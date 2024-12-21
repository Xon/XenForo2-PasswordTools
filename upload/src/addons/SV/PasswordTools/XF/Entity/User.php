<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * @extends \XF\Entity\User

 * @property-read UserAuth|null $Auth
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

    public function isForcing2Fa(): bool
    {
        return $this->hasPermission('general', 'svForceTfa');
    }
}