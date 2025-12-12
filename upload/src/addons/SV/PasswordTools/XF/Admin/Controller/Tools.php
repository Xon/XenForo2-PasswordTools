<?php

namespace SV\PasswordTools\XF\Admin\Controller;

use SV\PasswordTools\Repository\PasswordToolsRepository;
use XF\Mvc\Reply\AbstractReply;

/**
 * @extends \XF\Admin\Controller\Tools
 */
class Tools extends XFCP_Tools
{
    public function actionTestPasswordValidity(): ?AbstractReply
    {
        $repo = PasswordToolsRepository::get();

        $this->setSectionContext('svTestPasswordValidity');
        if (!$repo->canDoChecksAndTests())
        {
            return $this->noPermission();
        }

        $username = (string)$this->filter('username', 'str');
        $password = (string)$this->filter('password', 'str');
        $valid = false;
        $signupErrors = $errors = $warnings = [];
        $hasCheckedPassword = $this->isPost();
        if ($hasCheckedPassword)
        {
            $valid = $repo->validatePassword($username, $password, $errors, $warnings);
        }

        $viewParams = [
            'username' => $username,
            'password' => $password,
            'hasCheckedPassword' => $hasCheckedPassword,
            'isValid' => $valid,
            'signupErrors' => $signupErrors,
            'errors' => $errors,
            'warnings' => $warnings,
        ];

        return $this->view('', 'svPasswordTools_tools_test_password', $viewParams);
    }
}