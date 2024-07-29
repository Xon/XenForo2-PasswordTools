<?php

namespace SV\PasswordTools\XF\Repository;

/**
 * @extends \XF\Repository\User
 */
class User extends XFCP_User
{
    /** @noinspection PhpMissingReturnTypeInspection */
    public function setupBaseUser(?\XF\Entity\User $user = null)
    {
        $user = parent::setupBaseUser($user);

        // XF bug; the created entities don't link back to the User entity https://xenforo.com/community/threads/userrepo-setupbaseuser-doesnt-setup-dependant-entities-as-expected.223540/
        $user->Option->hydrateRelation('User', $user);
        $user->Profile->hydrateRelation('User', $user);
        $user->Privacy->hydrateRelation('User', $user);
        $user->Auth->hydrateRelation('User', $user);

        return $user;
    }
}