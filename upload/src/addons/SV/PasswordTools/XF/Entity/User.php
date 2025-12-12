<?php

namespace SV\PasswordTools\XF\Entity;

use SV\StandardLib\Helper;
use XF\Mvc\Entity\Structure;
use XF\Repository\Tfa as TfaRepo;
use function count;

/**
 * @extends \XF\Entity\User
 * @property-read UserAuth|null $Auth
 * @property-read bool $is2faForceEnabled
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

    protected function is2faForceEnabled(): bool
    {
        if (!$this->isForcing2Fa())
        {
            return false;
        }

        $tfaRepo = Helper::repository(TfaRepo::class);
        $providers = $tfaRepo->getAvailableProvidersForUser($this->user_id);
        unset($providers['backup']);
        unset($providers['email']);

        return count($providers) === 0;
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public static function getStructure(Structure $structure)
    {
        $structure = parent::getStructure($structure);

        $structure->getters['is2faForceEnabled'] = ['getter' => 'is2faForceEnabled', 'cache' => false];

        return $structure;
    }
}