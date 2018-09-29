<?php

namespace SV\PasswordTools\Option;

use XF\Entity\Option;
use XF\Option\AbstractOption;

/**
 * Class BlacklistPassword
 *
 * @package SV\PasswordTools\Option
 */
class BlacklistPassword extends AbstractOption
{
    /**
     * @param Option $option
     * @param array  $htmlParams
     *
     * @return string
     */
    public static function renderOption(Option $option, array $htmlParams)
    {
        $choices = [];
        foreach ($option->option_value AS $word)
        {
            $choices[] = $word;
        }

        return self::getTemplate('admin:option_template_svPasswordStrengthMeter_blacklist', $option, $htmlParams, [
            'choices' => $choices,
            'nextCounter' => count($choices)
        ]);
    }

    /**
     * @param array $value
     *
     * @return bool
     */
    public static function verifyOption(array &$value)
    {
        $output = [];

        foreach ($value AS $word)
        {
            $word = utf8_trim($word);
            if (empty($word))
            {
                continue;
            }

            $output[] = $word;
        }

        $value = $output;

        return true;
    }
}