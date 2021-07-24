<?php

namespace SV\PasswordTools;

use SV\StandardLib\InstallerHelper;
use XF\AddOn\AbstractSetup;
use XF\AddOn\StepRunnerInstallTrait;
use XF\AddOn\StepRunnerUninstallTrait;
use XF\AddOn\StepRunnerUpgradeTrait;
use XF\Db\Schema\Alter;
use XF\Db\Schema\Create;

class Setup extends AbstractSetup
{
    use InstallerHelper;
    use StepRunnerInstallTrait;
    use StepRunnerUpgradeTrait;
    use StepRunnerUninstallTrait;

    /**
     * Creates add-on tables.
     */
    public function installStep1(): void
    {
        $sm = $this->schemaManager();

        foreach ($this->getTables() as $tableName => $callback)
        {
            $sm->createTable($tableName, $callback);
            $sm->alterTable($tableName, $callback);
        }
    }

    public function installStep2()
    {
        $sm = $this->schemaManager();

        foreach ($this->getAlterTables() as $tableName => $callback)
        {
            if ($sm->tableExists($tableName))
            {
                $sm->alterTable($tableName, $callback);
            }
        }
    }

    public function upgrade2000000Step1(): void
    {
        $this->installStep1();
    }

    public function upgrade2000000Step2(): void
    {
        $this->renameOption('enforcePasswordComplexityForAdmins', 'svEnforcePasswordComplexityForAdmins');
        $this->renameOption('passwordToolsCheckTypes', 'svPasswordToolsCheckTypes');
        $this->renameOption('KL_PasswordCompare', 'svShowHidePassword');
        $this->renameOption('KL_PasswordStrengthMeter_min', 'svPasswordStrengthMeter_min');
        $this->renameOption('KL_PasswordStrengthMeter_str', 'svPasswordStrengthMeter_str');
        $this->renameOption('KL_PasswordStrengthMeter_force', 'svPasswordStrengthMeter_force');
        $this->renameOption('KL_PasswordStrengthMeter_blacklist', 'svPasswordStrengthMeter_blacklist');
        $this->renameOption('pwnedPasswordReuseCount', 'svPwnedPasswordReuseCount');
        $this->renameOption('pwnedPasswordCacheTime', 'svPwnedPasswordCacheTime');
    }

    public function upgrade2000000Step3(): void
    {
        /** @var \XF\Entity\Option $option */
        $option = \XF::finder('XF:Option')->whereId('svPasswordToolsCheckTypes')->fetchOne();
        if ($option)
        {
            $values = $option->option_value;
            $orderedValues = [
                'length' => true,
                'zxcvbn' => $values['zxcvbn'],
                'pwned'  => $values['pwned'],
            ];
            foreach ($values as $key => $val)
            {
                if (!isset($orderedValues[$key]))
                {
                    $orderedValues[$key] = $val;
                }
            }
            // order matters
            $option->option_value = $orderedValues;
            $option->saveIfChanged();
        }
    }

    public function upgrade3050000Step1(): void
    {
        $this->installStep1();
    }

    public function upgrade3050000Step2(): void
    {
        $this->installStep2();
    }

    /**
     * Drops add-on tables.
     */
    public function uninstallStep1(): void
    {
        $sm = $this->schemaManager();

        foreach ($this->getTables() as $tableName => $callback)
        {
            $sm->dropTable($tableName);
        }
    }


    public function uninstallStep2()
    {
        $sm = $this->schemaManager();

        foreach ($this->getTables() as $tableName => $callback)
        {
            $sm->dropTable($tableName);
        }
    }

    protected function getTables(): array
    {
        $tables = [];

        $tables['xf_sv_pwned_hash_cache'] = function ($table) {
            /** @var Create|Alter $table */
            $this->addOrChangeColumn($table, 'prefix', 'binary', 5);
            $this->addOrChangeColumn($table, 'suffixes', 'longblob');
            $this->addOrChangeColumn($table, 'last_update', 'int');

            $table->addPrimaryKey('prefix');
            $table->addKey(['last_update'], 'last_update');
        };

        return $tables;
    }

    protected function getAlterTables(): array
    {
        $tables = [];

        $tables['xf_user_authenticate'] = function (Alter $table) {
            $this->addOrChangeColumn($table, 'sv_pwned_password_check', 'int')->nullable()->setDefault(null);
        };

        return $tables;
    }

    protected function getRemoveAlterTables(): array
    {
        $tables = [];

        $tables['xf_user_authenticate'] = function (Alter $table) {
            $table->dropColumns('sv_pwned_password_check');
        };

        return $tables;
    }
}