<?php

namespace SV\PasswordTools\XF\Entity;

/**
 * Class UserAuth
 *
 * Extends \XF\Entity\UserAuth
 *
 * @package SV\PasswordTools\XF\Entity
 */
class UserAuth extends XFCP_UserAuth
{
    public function svCheckPasswordOnSet(string $password, int $updatePasswordDate, \Closure $parentCallable): bool
    {
        $options = $this->app()->options();

        if ($this->User)
        {
            $profile = $this->User->getRelation('Profile');
            if (!$updatePasswordDate || $profile && $profile->getOption('admin_edit') && !$options->svEnforcePasswordComplexityForAdmins)
            {
                return $parentCallable();
            }
        }

        foreach ($options->svPasswordToolsCheckTypes AS $checkType => $check)
        {
            if ($check)
            {
                $checkMethodFunc = [$this, 'checkPasswordWith' . \XF\Util\Php::camelCase($checkType)];
                if (\is_callable($checkMethodFunc))
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

        return $parentCallable();
    }

    protected function checkPasswordWithLength(string $password): bool
    {
        $options = $this->app()->options();

        $minLength = $options->svPasswordStrengthMeter_min;
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

        $zxcvbn = new \ZxcvbnPhp\Zxcvbn();

        $blackList = array_merge($options->svPasswordStrengthMeter_blacklist, [$options->boardTitle]);
        $result = $zxcvbn->passwordStrength($password, $blackList);

        if ($result['score'] < $options->svPasswordStrengthMeter_str)
        {
            $this->error(\XF::phrase('svPasswordStrengthMeter_error_TooWeak'), 'password');

            return false;
        }

        if ($options->svPasswordStrengthMeter_force && !empty($result['sequence']))
        {
            /** @var \ZxcvbnPhp\Matchers\DictionaryMatch $matchSequence */
            foreach ($result['sequence'] AS $matchSequence)
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
        $options = $this->app()->options();
        $minimumUsages = (int)$options->svPwnedPasswordReuseCount;

        if ($minimumUsages < 1)
        {
            return true;
        }

        $hash = utf8_strtoupper(sha1($password));
        $prefix = utf8_substr($hash, 0, 5);
        $suffix = utf8_substr($hash, 5);
        $suffixSet = $this->getPwnedPrefixMatches($prefix, null);
        if ($suffixSet === null)
        {
            return true;
        }

        if (isset($suffixSet[$suffix]) &&
            ($useCount = $suffixSet[$suffix]) &&
            $useCount >= $minimumUsages)
        {
            $this->error(\XF::phrase('svPasswordTools_password_known_to_be_compromised_on_at_least_x_accounts', [
                'count'          => $useCount,
                'countFormatted' => \XF::language()->numberFormat($useCount)
            ]), 'password');

            return false;
        }

        return true;
    }

    protected function getPwnedPrefixMatches(string $prefix, ?int $cutoff): ?array
    {
        $options = $this->app()->options();
        $db = $this->db();

        if ($cutoff === null)
        {
            $pwnedPasswordCacheTime = (int)$options->svPwnedPasswordCacheTime;
            if ($pwnedPasswordCacheTime > 0)
            {
                $cutoff = \XF::$time - $pwnedPasswordCacheTime * 86400;
            }
        }

        $cutoff = $cutoff ?: 0;
        $suffixes = $db->fetchOne(
            'SELECT suffixes
                    FROM xf_sv_pwned_hash_cache
                    WHERE prefix = ?
                      AND last_update > ?', [$prefix, $cutoff]
        );

        if ($suffixes)
        {
            $suffixSet = @json_decode($suffixes, true);
            if (\is_array($suffixSet))
            {
                return $suffixSet;
            }
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
                $suffixCount = [];
                $error = $error ?: \XF::phrase('svPasswordTools_API_Failure')->render();
                \XF::logError($error);
            }
            else if ($response->getStatusCode() !== 200)
            {
                $publicError = \XF::phrase('svPasswordTools_API_Failure_code', ['code' => $response->getStatusCode()]);
                $error = $error ?: '';
                \XF::logError("$publicError\n {$error}");
                $this->error($publicError, 'password');

                return null;
            }
            else
            {
                $text = $response->getBody();
                $suffixSet = array_filter(array_map('trim', explode("\n", $text)));
                foreach ($suffixSet as $suffix)
                {
                    $suffixInfo = explode(':', utf8_trim($suffix));
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
}