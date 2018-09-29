<?php

// ################## THIS IS A GENERATED FILE ##################
// #################### DO NOT EDIT DIRECTLY ####################

namespace SV\PasswordTools;

/**
 * Class FakeComposer
 *
 * @package SV\PasswordTools
 */
class FakeComposer
{
    /**
     * @return array
     */
    protected static function getNamespaces()
    {
        /** @noinspection PhpTraditionalSyntaxArrayLiteralInspection */
        return array (
);
    }

    /**
     * @return array
     */
    protected static function getPsr4()
    {
        /** @noinspection PhpTraditionalSyntaxArrayLiteralInspection */
        return array (
  'ZxcvbnPhp\\' => 
  array (
    0 => 'src/addons/SV/PasswordTools/vendor/bjeavons/zxcvbn-php/src',
  ),
);
    }

    /**
     * @return array
     */
    protected static function getClassMap()
    {
        /** @noinspection PhpTraditionalSyntaxArrayLiteralInspection */
        return array (
);
    }

    /**
     * @return array
     */
    protected static function getRequiredFiles()
    {
        /** @noinspection PhpTraditionalSyntaxArrayLiteralInspection */
        return array (
);
    }
    
    /**
     * @param \XF\App $app
     */
    public static function appSetup(\XF\App $app)
    {
        foreach (self::getNamespaces() AS $namespace => $filePath)
        {
            \XF::$autoLoader->add($namespace, $filePath);
        }

        foreach (self::getPsr4() AS $namespace => $filePath)
        {
            \XF::$autoLoader->addPsr4($namespace, $filePath, true);
        }

        \XF::$autoLoader->addClassMap(self::getClassMap());
        
        $xfRoot = \XF::getRootDirectory();

        foreach (self::getRequiredFiles() AS $filePath)
        {
            $_filePath = $xfRoot . DIRECTORY_SEPARATOR . $filePath;
            
            if (file_exists($_filePath) && is_readable($_filePath))
            {
                require $_filePath;
            }
            else
            {
                throw new \InvalidArgumentException("{$_filePath} does not exist.");
            }
        }
    }
}