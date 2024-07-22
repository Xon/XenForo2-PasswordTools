<?php

namespace SV\PasswordTools\XF\Entity;

use SV\StandardLib\Helper;
use XF\Mvc\Entity\Structure;
use XF\Repository\UserAlert as UserAlertRepo;
use XF\Service\User\UserGroupChange as UserGroupChangeService;
use XF\Util\Php;
use ZxcvbnPhp\Matchers\DictionaryMatch;
use ZxcvbnPhp\Zxcvbn;
use function is_callable, mb_strlen, array_merge, strtoupper, sha1, substr, json_decode, is_array, array_filter,array_map,explode,trim;
use function json_encode;
use function strlen;

/**
 * @extends \XF\Entity\UserAuth
 *
 * @property int|null $sv_pwned_password_check
 */
class UserAuth extends XFCP_UserAuth
{
    protected $svZxcvbnMaxPasswordLength = 256;

    public function svCheckPasswordOnSet(string $password, int $updatePasswordDate, \Closure $parentCallable): bool
    {
        if (!$updatePasswordDate || $this->getOption('svAutomatedEdit'))
        {
            // The user's password isn't changing; the auth class or config is just being updated, e.g. switching from bcrypt to argon2 or rounds
            //return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
            return $parentCallable();
        }

        $options = \XF::options();

        if (!($options->svEnforcePasswordComplexityForAdmins ?? false) && $this->getOption('svAdminEdit'))
        {
            // Password checks are disabled in admin.php, and this is happening in admin.php or via an automated process
            //return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
            return $parentCallable();
        }

        foreach (($options->svPasswordToolsCheckTypes ?? []) as $checkType => $check)
        {
            if ($check)
            {
                $checkMethodFunc = [$this, 'checkPasswordWith' . Php::camelCase($checkType)];
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

        //return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
        return $parentCallable();
    }

    protected function checkPasswordWithLength(string $password): bool
    {
        $options = \XF::options();

        $minLength = (int)($options->svPasswordStrengthMeter_min ?? 8);
        if (mb_strlen($password) < $minLength)
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
        $options = \XF::options();

        // Zxcvbn is vulnerable to a Denial of Service attack when the raw password is too long
        if (strlen($password) > $this->svZxcvbnMaxPasswordLength)
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_password_too_long', [
                'maxLength' => $this->svZxcvbnMaxPasswordLength,
            ]), 'password');

            return false;
        }

        $zxcvbn = new Zxcvbn();

        $blackList = array_merge(($options->svPasswordStrengthMeter_blacklist ?? []), [$options->boardTitle]);
        $result = $zxcvbn->passwordStrength($password, $blackList);

        if ($result['score'] < (int)($options->svPasswordStrengthMeter_str ?? 0))
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_error_TooWeak'), 'password');

            return false;
        }

        if (($options->svPasswordStrengthMeter_force ?? false) && !empty($result['sequence']))
        {
            /** @var DictionaryMatch $matchSequence */
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
            $this->setOption('svNagOnWeakPassword', $useCount);

            $this->error(\XF::phrase('svPasswordTools_password_known_to_be_compromised_on_at_least_x_accounts', [
                'count'          => $useCount,
                'countFormatted' => \XF::language()->numberFormat($useCount)
            ]), 'password');

            return false;
        }

        return true;
    }

    protected function checkPasswordWithKnownBad(string $password): bool
    {
        if ($this->isPasswordEmailOrUsername($password))
        {
            $this->error(\XF::phrase('svPasswordTools_password_must_not_contain_your_email_address_or_username', [
            ]), 'password');

            return false;
        }

        if ($this->isPasswordSiteInfo($password))
        {
            $this->error(\XF::phrase('svPasswordTools_password_must_not_contain_site_information', [
            ]), 'password');

            return false;
        }

        return true;
    }

    public function isPasswordEmailOrUsername(string $password): bool
    {
        // people using emails/usernames as password is :|
        $email = $this->User->email;
        $username = $this->User->username;

        return mb_stripos($email, $password) !== false
               || mb_stripos($username, $password) !== false
        ;
    }

    public function isPasswordSiteInfo(string $password): bool
    {
        $options = \XF::options();

        return mb_stripos($options->boardTitle, $password) !== false
               || mb_stripos($options->boardUrl, $password) !== false
            ;
    }

    public function isPwnedPassword(string $password, int &$useCount, bool $cacheOnly): bool
    {
        $options = \XF::options();

        $minimumUsages = (int)($options->svPwnedPasswordReuseCount ?? 0);
        $minimumUsagesSoft = (int)($options->svPwnedPasswordReuseCountSoft ?? 0);

        if ($minimumUsages < 1 && $minimumUsagesSoft < 1)
        {
            return false;
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

        $minimumUsagesSoft = (int)(\XF::options()->svPwnedPasswordReuseCountSoft ?? 0);
        if ($minimumUsagesSoft !== 0 && $useCount >= $minimumUsagesSoft)
        {
            $this->setOption('svResetPwnedPasswordCheck', false);
            $this->setOption('svNagOnWeakPassword', $useCount);
        }

        return false;
    }

    public function isCompromisedPassword(string $password, int &$useCount): bool
    {
        if ($this->isPwnedPassword($password, $useCount, false))
        {
            return true;
        }

        if (!(\XF::options()->svOnLoginConsiderKnownBadAsCompromised ?? false))
        {
            return false;
        }

        if ($this->isPasswordEmailOrUsername($password))
        {
            $useCount = 1;
            return true;
        }

        if ($this->isPasswordSiteInfo($password))
        {
            $useCount = 1;
            return true;
        }

        return false;
    }

    protected function getPwnedPrefixMatches(string $prefix, ?int $cacheCutoff, bool $cacheOnly): ?array
    {
        $options = \XF::options();
        $db = \XF::db();

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

        if ($this->isUpdate() && $this->isChanged('data'))
        {
            if ($this->sv_pwned_password_check && $this->getOption('svResetPwnedPasswordCheck'))
            {
                $this->fastUpdate('sv_pwned_password_check', null);
                // this will touch the xf_user record
                $this->svClearCompromisedPasswordStateLater();
            }

            $useCount = (int)$this->getOption('svNagOnWeakPassword');
            if ($useCount !== 0)
            {
                $this->flagPwnedPasswordCheck();
                $this->svNagOnWeakPasswordDefer($useCount);
            }
        }
    }

    protected function svClearCompromisedPasswordStateLater(): void
    {
        \XF::runOnce('svCompromisedPassword'.$this->user_id, function() {
            $this->svClearCompromisedPasswordState();
        });
    }

    protected function svClearCompromisedPasswordState(): void
    {
        $alertRepo = Helper::repository(UserAlertRepo::class);
        $alertRepo->fastDeleteAlertsToUser($this->user_id, 'user', $this->user_id, 'pwned_password');
        $userGroupChangeService = Helper::service(UserGroupChangeService::class);
        $userGroupChangeService->removeUserGroupChange($this->user_id, 'svCompromisedPassword');
    }

    public function flagPwnedPasswordCheck(): void
    {
        $this->fastUpdate('sv_pwned_password_check', \XF::$time);
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
        $alertRepo = Helper::repository(UserAlertRepo::class);
        $alertRepo->alert(
            $this->User,
            0, '',
            'user', $this->User->user_id,
            'pwned_password', [
                'depends_on_addon_id' => 'SV/PasswordTools',
                'count'               => $useCount,
                'countFormatted'      => \XF::language()->numberFormat($useCount),
            ]
        );
    }

    public function hasPwnedPassword(): bool
    {
        if ($this->getOption('svForcePwnedPassword'))
        {
            return true;
        }

        $pwnedPasswordTimestamp = (int)$this->sv_pwned_password_check;
        if ($pwnedPasswordTimestamp !== 0)
        {
            return true;
        }

        return false;
    }

    public function svIsForceEmail2Fa(): bool
    {
        return \XF::config('enableTfa') && (\XF::options()->svPwnedPasswordForceEmail2FA ?? false);
    }

    /** @noinspection PhpMissingReturnTypeInspection */
    public static function getStructure(Structure $structure)
    {
        $structure = parent::getStructure($structure);

        $structure->columns['sv_pwned_password_check'] = ['type' => self::UINT, 'default' => null, 'nullable' => true, 'changeLog' => false];
        $structure->options['svForcePwnedPassword'] = false;
        $structure->options['svResetPwnedPasswordCheck'] = true;
        $structure->options['svNagOnWeakPassword'] = 0;
        $structure->options['svAdminEdit'] = false;
        $structure->options['svAutomatedEdit'] = false;

        return $structure;
    }
}