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
    /**
     * @param string      $password
     * @param string|null $authClass
     * @param bool        $updatePasswordDate
     * @return bool
     */
    public function setPassword($password, $authClass = null, $updatePasswordDate = true)
    {
        $options = $this->app()->options();

        if ($this->User)
        {
            $profile = $this->User->getRelation('Profile');
            if (!$updatePasswordDate || $profile && $profile->getOption('admin_edit') && !$options->svEnforcePasswordComplexityForAdmins)
            {
                return parent::setPassword($password, $authClass, $updatePasswordDate);
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

        return parent::setPassword($password, $authClass, $updatePasswordDate);
    }

    /**
     * @param $password
     * @return bool
     */
    protected function checkPasswordWithLength($password)
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


    /**
     * @param $password
     * @return bool
     */
    protected function checkPasswordWithZxcvbn($password)
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

        if ($options->svPasswordStrengthMeter_force)
        {
            /** @var \ZxcvbnPhp\Matchers\DictionaryMatch $matchSequence */
            foreach ($result['match_sequence'] AS $matchSequence)
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

    /**
     * @param string $password
     * @return bool
     * @throws \XF\Db\Exception
     */
    protected function checkPasswordWithPwned($password)
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
        $suffixSet = $this->getPwnedPrefixMatches($prefix);
        if ($suffixSet === null || $suffixSet === false)
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

    /**
     * @param string   $prefix
     * @param null|int $cutoff
     * @return array|bool
     * @throws \XF\Db\Exception
     */
    protected function getPwnedPrefixMatches($prefix, $cutoff = null)
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
            $request = $this->app()->http()->reader()->getUntrusted('https://api.pwnedpasswords.com/range/' . $prefix, [], null, [
                'timeout' => 2,
                'headers' => [
                    'User-Agent' => 'XenForo/' . \XF::$version . '(' . $options->boardUrl . ')'
                ]
            ]);

            if (!$request)
            {
                $this->error(\XF::phrase('svPasswordTools_API_Failure'), 'password');

                return false;
            }
            else if ($request->getStatusCode() !== 200)
            {
                $this->error(\XF::phrase('svPasswordTools_API_Failure_code', ['code' => $request->getStatusCode()]), 'password');

                return false;
            }

            $text = $request->getBody();
            $suffixSet = array_filter(array_map('trim', explode("\n", $text)));
            foreach ($suffixSet as $suffix)
            {
                $suffixInfo = explode(':', utf8_trim($suffix));
                $suffixCount[$suffixInfo[0]] = (int)$suffixInfo[1];
            }
        }
        catch (\Exception $e)
        {
            // since sanitizinig Exception is too hard, and setPassword will contain the password!!, swallow the exception
            //\XF::logException($e, false);

            $this->error(\XF::phrase('svPasswordTools_API_Failure'), 'password');

            return false;
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