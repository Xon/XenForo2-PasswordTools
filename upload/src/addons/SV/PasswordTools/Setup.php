<?php

namespace SV\PasswordTools;

use SV\Utils\InstallerHelper;
use XF\AddOn\AbstractSetup;
use XF\AddOn\StepRunnerInstallTrait;
use XF\AddOn\StepRunnerUninstallTrait;
use XF\AddOn\StepRunnerUpgradeTrait;
use XF\Db\Schema\Alter;
use XF\Db\Schema\Create;
use XF\Entity\User;

class Setup extends AbstractSetup
{
    use InstallerHelper;
    use StepRunnerInstallTrait;
    use StepRunnerUpgradeTrait;
    use StepRunnerUninstallTrait;

    /**
     * Creates add-on tables.
     */
    public function installStep1()
    {
        $sm = $this->schemaManager();

        foreach ($this->getTables() as $tableName => $callback)
        {
            $sm->createTable($tableName, $callback);
            $sm->alterTable($tableName, $callback);
        }
    }

    public function upgrade2000000Step1()
    {
        $this->installStep1();
    }

    public function upgrade2000000Step2()
    {
        $this->renameOption('enforcePasswordComplexityForAdmins','svEnforcePasswordComplexityForAdmins');
        $this->renameOption('passwordToolsCheckTypes','svPasswordToolsCheckTypes');
        $this->renameOption('KL_PasswordStrengthMeter_min','svPasswordStrengthMeter_min');
        $this->renameOption('KL_PasswordStrengthMeter_str','svPasswordStrengthMeter_str');
        $this->renameOption('KL_PasswordStrengthMeter_force','svPasswordStrengthMeter_force');
        $this->renameOption('KL_PasswordStrengthMeter_blacklist','svPasswordStrengthMeter_blacklist');
        $this->renameOption('pwnedPasswordReuseCount','svPwnedPasswordReuseCount');
        $this->renameOption('pwnedPasswordCacheTime','svPwnedPasswordCacheTime');
    }

    /**
     * Drops add-on tables.
     */
    public function uninstallStep1()
    {
        $sm = $this->schemaManager();

        foreach ($this->getTables() as $tableName => $callback)
        {
            $sm->dropTable($tableName);
        }
    }

    /**
     * @return array
     */
    protected function getTables()
    {
        $tables = [];

        $tables['xf_sv_pwned_hash_cache'] = function ($table) {
            /** @var Create|Alter $table */
            $this->addOrChangeColumn($table, 'prefix', 'binary', 5);
            $this->addOrChangeColumn($table, 'suffixes', 'blob');
            $this->addOrChangeColumn($table, 'last_update', 'int');

            $table->addPrimaryKey('prefix');
            $table->addKey(['last_update'], 'last_update');
        };

        return $tables;
    }
}