<?php

namespace SV\PasswordTools\Repository;

use SV\PasswordTools\XF\Entity\UserAuth as ExtendedUserAuth;
use SV\StandardLib\Helper;
use XF\Entity\AdminNavigation as AdminNavigationEntity;
use XF\Mvc\Entity\Repository;
use XF\Repository\User as UserRepository;
use XF\Entity\User as UserEntity;

class PasswordToolsRepository extends Repository
{
    public static function get(): self
    {
        return Helper::repository(self::class);
    }

    public function canDoChecksAndTests(): bool
    {
        if (\XF::$versionId < 2030470)
        {
            return true;
        }

        return \XF::visitor()->hasAdminPermission('checksAndTests');
    }

    public function shimAdminNavigation(): void
    {
        $navEntry = Helper::find(AdminNavigationEntity::class, 'svValidateEmail');
        if ($navEntry !== null)
        {
            $navEntry->admin_permission_id = \XF::$versionId >= 2030470 ? 'checksAndTests' : '';
            $navEntry->saveIfChanged();
        }
    }

    public function validatePassword(string $username, string $password, array &$errors, array &$warnings): bool
    {
        $errors = $warnings = [];

        $user = Helper::findOne(UserEntity::class, [
            'username' => $username,
        ]);
        if ($user === null)
        {
            if ($username !== '')
            {
                $warnings[] = \XF::phrase('svPasswordTools_password.user_not_found', ['user' => $username]);
            }

            $user = Helper::repository(UserRepository::class)->getGuestUser();
        }
        /** @var ExtendedUserAuth $userAuth */
        $userAuth = $user->getRelationOrDefault('Auth');

        return $userAuth->doPasswordChecks($password, $errors, $warnings);
    }
}