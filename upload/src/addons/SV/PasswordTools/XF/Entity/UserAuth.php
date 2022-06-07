<?php

namespace SV\PasswordTools\XF\Entity;

use XF\Mvc\Entity\Structure;
use function is_callable, utf8_strlen, strlen, array_merge, strtoupper, sha1, substr, json_decode, is_array, array_filter,array_map,explode,trim;

/**
 * Class UserAuth
 * Extends \XF\Entity\UserAuth
 *
 * @package SV\PasswordTools\XF\Entity
 * @property int|null sv_pwned_password_check
 */
class UserAuth extends XFCP_UserAuth
{
    protected $svZxcvbnMaxPasswordLength = 256;

    /** @noinspection PhpMissingReturnTypeInspection */
    public function setPassword($password, $authClass = null, $updatePasswordDate = true, $allowReuse = true)
    {
        $options = $this->app()->options();

        $user = $this->User;
        if ($user)
        {
            $applyToAdminEdit = (bool)($options->svEnforcePasswordComplexityForAdmins ?? false);
            $isAdminEdit = $user->getOption('admin_edit');
            $profile = $user->getRelation('Profile');
            if ($profile && $profile->getOption('admin_edit'))
            {
                $isAdminEdit = true;
            }
            if (!$updatePasswordDate || $isAdminEdit && !$applyToAdminEdit)
            {
                return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
            }
        }

        foreach (($options->svPasswordToolsCheckTypes ?? []) as $checkType => $check)
        {
            if ($check)
            {
                $checkMethodFunc = [$this, 'checkPasswordWith' . \XF\Util\Php::camelCase($checkType)];
                if (is_callable($checkMethodFunc))
                {
                    if (!$checkMethodFunc($password))
                    {
                        break;
                    }
                }
            }
        }

        if ($this->hasErrors())
        {
            return false;
        }

        return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
    }

    protected function checkPasswordWithLength(string $password): bool
    {
        $options = $this->app()->options();

        $minLength = (int)($options->svPasswordStrengthMeter_min ?? 8);
        if (utf8_strlen($password) < $minLength)
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_Password_must_be_X_characters', [
                'length' => $minLength
            ]), 'password');

            return false;
        }

        return true;
    }

    protected function checkPasswordWithZxcvbn(string $password): bool
    {
        $options = $this->app()->options();

        // Zxcvbn is vulnerable to a Denial of Service attack when the raw password is too long
        if (strlen($password) > $this->svZxcvbnMaxPasswordLength)
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_password_too_long', [
                'maxLength' => $this->svZxcvbnMaxPasswordLength,
            ]), 'password');

            return false;
        }

        $zxcvbn = new \ZxcvbnPhp\Zxcvbn();

        $blackList = array_merge(($options->svPasswordStrengthMeter_blacklist ?? []), [$options->boardTitle]);
        $result = $zxcvbn->passwordStrength($password, $blackList);

        if ($result['score'] < (int)($options->svPasswordStrengthMeter_str ?? 0))
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_error_TooWeak'), 'password');

            return false;
        }

        if (($options->svPasswordStrengthMeter_force ?? false) && !empty($result['sequence']))
        {
            /** @var \ZxcvbnPhp\Matchers\DictionaryMatch $matchSequence */
            foreach ($result['sequence'] as $matchSequence)
            {
                if (isset($matchSequence->dictionaryName) && $matchSequence->dictionaryName === 'user_inputs')
                {
                    $this->error(\XF::phrase('svPasswordStrengthMeter_errorInvalidExpression'), 'password');

                    return false;
                }
            }
        }

        return true;
    }

    protected function checkPasswordWithPwned(string $password): bool
    {
        $useCount = 0;
        $pwnedPassword = $this->isPwnedPassword($password, $useCount, false);
        if ($pwnedPassword)
        {
            $this->error(\XF::phrase('svPasswordTools_password_known_to_be_compromised_on_at_least_x_accounts', [
                'count'          => $useCount,
                'countFormatted' => \XF::language()->numberFormat($useCount)
            ]), 'password');

            return false;
        }

        return true;
    }

    public function isPwnedPassword(string $password, int &$useCount, bool $cacheOnly): bool
    {
        $options = $this->app()->options();
        $minimumUsages = (int)($options->svPwnedPasswordReuseCount ?? 0);
        $minimumUsagesSoft = (int)($options->svPwnedPasswordReuseCountSoft ?? 0);

        if ($minimumUsages < 1 && $minimumUsagesSoft < 1)
        {
            return true;
        }

        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);
        $suffixSet = $this->getPwnedPrefixMatches($prefix, null, $cacheOnly);
        if ($suffixSet === null)
        {
            return false;
        }

        $useCount = (int)($suffixSet[$suffix] ?? 0);

        if ($useCount === 0)
        {
            return false;
        }

        if ($minimumUsages !== 0 && $useCount >= $minimumUsages)
        {
            return true;
        }

        if ($minimumUsagesSoft !== 0 && $useCount >= $minimumUsagesSoft)
        {
            $this->setOption('svResetPwnedPasswordCheck', false);
            $this->setOption('svNagOnWeakPassword', $useCount);
        }

        return false;
    }

    protected function getPwnedPrefixMatches(string $prefix, ?int $cacheCutoff, bool $cacheOnly): ?array
    {
        $options = $this->app()->options();
        $db = $this->db();

        if ($cacheCutoff === null)
        {
            $pwnedPasswordCacheTime = (int)($options->svPwnedPasswordCacheTime ?? 7);
            if ($pwnedPasswordCacheTime > 0)
            {
                $cacheCutoff = \XF::$time - $pwnedPasswordCacheTime * 86400;
            }
        }

        $cacheCutoff = (int)$cacheCutoff;
        $suffixes = $db->fetchOne(
            'SELECT suffixes
                    FROM xf_sv_pwned_hash_cache
                    WHERE prefix = ?
                      AND last_update > ?', [$prefix, $cacheCutoff]
        );

        if ($suffixes)
        {
            $suffixSet = @json_decode($suffixes, true);
            if (is_array($suffixSet))
            {
                return $suffixSet;
            }
        }

        if ($cacheOnly)
        {
            return [];
        }

        $suffixCount = [];
        try
        {
            $response = $this->app()->http()->reader()->getUntrusted('https://api.pwnedpasswords.com/range/' . $prefix, [], null, [
                'timeout' => 2,
                'headers' => [
                    'User-Agent' => 'XenForo/' . \XF::$version . '(' . $options->boardUrl . ')'
                ]
            ], $error);

            if (!$response)
            {
                $publicError = \XF::phrase('svPasswordTools_API_Failure');
                $error = $error ?: $publicError->render();
                \XF::logError($error);
                $this->error($publicError, 'password');

                return null;
            }
            else if ($response->getStatusCode() === 404)
            {
                // the API shouldn't return 404, but handle it anyway
                $error = $error ?: \XF::phrase('svPasswordTools_API_Failure')->render();
                \XF::logError($error);
            }
            else if ($response->getStatusCode() !== 200)
            {
                $publicError = \XF::phrase('svPasswordTools_API_Failure_code', ['code' => $response->getStatusCode()]);
                $error = $error ?: '';
                \XF::logError("$publicError\n $error");
                $this->error($publicError, 'password');

                return null;
            }
            else
            {
                $text = $response->getBody();
                $suffixSet = array_filter(array_map('\trim', explode("\n", $text)));
                foreach ($suffixSet as $suffix)
                {
                    $suffixInfo = explode(':', trim($suffix));
                    $suffixCount[$suffixInfo[0]] = (int)$suffixInfo[1];
                }
            }
        }
        catch (\Exception $e)
        {
            // XF sanitise the stack trace, so this is safe
            \XF::logException($e);

            $this->error(\XF::phrase('svPasswordTools_API_Failure'), 'password');

            return null;
        }
        $db->query('INSERT INTO xf_sv_pwned_hash_cache (prefix, suffixes, last_update)
          VALUES (?,?,?)
          ON DUPLICATE KEY UPDATE
            suffixes = VALUES(suffixes),
            last_update = VALUES(last_update)
         ', [$prefix, json_encode($suffixCount), \XF::$time]);

        return $suffixCount;
    }

    protected function _postSave()
    {
        parent::_postSave();

        if ($this->isChanged('data'))
        {
            if ($this->getOption('svResetPwnedPasswordCheck'))
            {
                $this->fastUpdate('sv_pwned_password_check', 0);
                /** @var \XF\Repository\UserAlert $alertRepo */
                $alertRepo = $this->repository('XF:UserAlert');
                $alertRepo->fastDeleteAlertsToUser($this->user_id, 'user', $this->user_id, 'pwned_password');
            }

            $useCount = $this->getOption('svNagOnWeakPassword');
            if ($useCount)
            {
                $this->svNagOnWeakPasswordDefer($useCount);
            }
        }
    }

    public function svNagOnWeakPasswordDefer(int $useCount): void
    {
        \XF::runLater(function () use ($useCount) {
            try
            {
                $this->svNagOnWeakPassword($useCount);
            }
            catch (\Throwable $e)
            {
                \XF::logException($e);
            }
        });
    }

    public function svNagOnWeakPassword(int $useCount): void
    {
        $this->fastUpdate('sv_pwned_password_check', \XF::$time);
        /** @var \XF\Repository\UserAlert $alertRepo */
        $alertRepo = $this->repository('XF:UserAlert');
        $alertRepo->alert(
            $this->User,
            0, '',
            'user', $this->User->user_id,
            "pwned_password", [
                'depends_on_addon_id' => 'SV/PasswordTools',
                'count'               => $useCount,
                'countFormatted'      => \XF::language()->numberFormat($useCount),
            ]
        );
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public static function getStructure(Structure $structure)
    {
        $structure = parent::getStructure($structure);

        $structure->columns['sv_pwned_password_check'] = ['type' => self::UINT, 'default' => null, 'nullable' => true, 'changeLog' => false];
        $structure->options['svResetPwnedPasswordCheck'] = true;
        $structure->options['svNagOnWeakPassword'] = 0;

        return $structure;
    }
}