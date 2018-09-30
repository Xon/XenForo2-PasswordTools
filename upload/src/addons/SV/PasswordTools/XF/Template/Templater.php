<?php

namespace SV\PasswordTools\XF\Template;



/**
 * Extends \XF\Template\Templater
 */
class Templater extends XFCP_Templater
{
    protected $svPasswordToolsRecursionGuard = false;

    public function formTextBoxRow(array $controlOptions, array $rowOptions)
    {
        if (!$this->svPasswordToolsRecursionGuard &&
            isset($controlOptions['type']) && $controlOptions['type'] === 'password')
        {
            $this->svPasswordToolsRecursionGuard = true;
            try
            {
                unset($controlOptions['type']);
                return $this->svPasswordTextBoxRow($controlOptions, $rowOptions);
            }
            finally
            {
                $this->svPasswordToolsRecursionGuard = false;
            }
        }

        return parent::formTextBoxRow($controlOptions, $rowOptions);
    }

    public function formTextBox(array $controlOptions)
    {
        if (!$this->svPasswordToolsRecursionGuard &&
            isset($controlOptions['type']) && $controlOptions['type'] === 'password')
        {
            $this->svPasswordToolsRecursionGuard = true;
            try
            {
                if (empty($rowOptions['data-xf-init']))
                {
                    $rowOptions['data-xf-init'] = 'password-input';
                }

                unset($controlOptions['type']);
                $wrap = $this->processAttributeToRaw($controlOptions, 'wrap');
                return $this->svPasswordTextBox($controlOptions, $wrap);
            }
            finally
            {
                $this->svPasswordToolsRecursionGuard = false;
            }
        }

        return parent::formTextBox($controlOptions);
    }

    public function svPasswordTextBoxRow(array $controlOptions, array $rowOptions)
    {
        $this->addToClassAttribute($rowOptions, 'formRow--input', 'rowclass');

        if (empty($rowOptions['data-xf-init']))
        {
            $rowOptions['data-xf-init'] = 'password-input';
        }

        $controlId = $this->assignFormControlId($controlOptions);
        $controlHtml = $this->svPasswordTextBox($controlOptions);
        return $this->formRow($controlHtml, $rowOptions, $controlId);
    }

    public function svPasswordTextBox(array $controlOptions, $wrap = false)
    {
        $this->processCodeAttribute($controlOptions);
        $class = $this->processAttributeToRaw($controlOptions, 'class', '', true);
        $xfInit = $this->processAttributeToRaw($controlOptions, 'data-xf-init', '', true);

        $showPasswordStrength = $this->processAttributeToRaw($controlOptions, 'show-strength');
        $name = $this->processAttributeToRaw($controlOptions, 'name');
        $password = $this->processAttributeToRaw($controlOptions, 'value');
        $explain = $this->processAttributeToRaw($controlOptions, 'explain');
        $label = $this->processAttributeToRaw($controlOptions, 'label');
        $required = $this->processAttributeToRaw($controlOptions, 'required');
        $disabled = $this->processAttributeToRaw($controlOptions, 'disabled');
        $autofocus = $this->processAttributeToRaw($controlOptions, 'autofocus');

        return $this->renderMacro('public:svPasswordTools_macros', 'password_input' . ($wrap ? '_wrap' : ''), [
            'class' => $class,
            'xfInit' => $xfInit,
            'inputName' => $name,
            'password' => $password,
            'explain' => $explain,
            'label' => $label,
            'required' => $required,
            'disabled' => $disabled,
            'autofocus' => $autofocus,
            'showPasswordStrength' => $showPasswordStrength,
            // unhandled attributes, maybe the template will do something with it?
            'controlOptions' => $controlOptions,
        ]);
    }
}