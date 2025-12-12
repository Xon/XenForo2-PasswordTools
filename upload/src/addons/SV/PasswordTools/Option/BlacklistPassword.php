<?php

namespace SV\PasswordTools\Option;

use XF\Entity\Option as OptionEntity;
use XF\Option\AbstractOption;
use function count;
use function trim, strlen;

class BlacklistPassword extends AbstractOption
{
    public static function renderOption(OptionEntity $option, array $htmlParams): string
    {
        $choices = [];
        foreach ($option->option_value as $word)
        {
            $choices[] = $word;
        }

        return self::getTemplate('admin:option_template_svPasswordStrengthMeter_blacklist', $option, $htmlParams, [
            'choices'     => $choices,
            'nextCounter' => count($choices)
        ]);
    }

    public static function verifyOption(array &$value): bool
    {
        $output = [];

        foreach ($value as $word)
        {
            $word = trim($word);
            if (strlen($word) === 0)
            {
                continue;
            }

            $output[] = $word;
        }

        $value = $output;

        return true;
    }
}