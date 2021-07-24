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
    public static function renderOption(Option $option, array $htmlParams): string
    {
        $choices = [];
        foreach ($option->option_value AS $word)
        {
            $choices[] = $word;
        }

        return self::getTemplate('admin:option_template_svPasswordStrengthMeter_blacklist', $option, $htmlParams, [
            'choices'     => $choices,
            'nextCounter' => \count($choices)
        ]);
    }

    public static function verifyOption(array &$value): bool
    {
        $output = [];

        foreach ($value AS $word)
        {
            $word = \utf8_trim($word);
            if (\strlen($word) === 0)
            {
                continue;
            }

            $output[] = $word;
        }

        $value = $output;

        return true;
    }
}