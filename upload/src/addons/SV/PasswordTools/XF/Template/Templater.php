<?php

namespace SV\PasswordTools\XF\Template;

/**
 * XF2.1 mostly uses formPasswordBox/formPasswordBoxRow, formTextBoxRow/formTextBox with type="password" is only used in one spot (admin login)
 *
 * Extends \XF\Template\Templater
 */
class Templater extends XFCP_Templater
{
    protected $svPasswordToolsRecursionGuard = false;

    /**
     * @param array $controlOptions
     * @param array $rowOptions
     *
     * @return string
     */
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

    /**
     * @param array $controlOptions
     *
     * @return mixed|string
     */
    public function formTextBox(array $controlOptions)
    {
        if (!$this->svPasswordToolsRecursionGuard &&
            isset($controlOptions['type']) && $controlOptions['type'] === 'password')
        {
            $this->svPasswordToolsRecursionGuard = true;
            try
            {
                if (empty($controlOptions['data-xf-init']))
                {
                    $controlOptions['data-xf-init'] = 'password-input';
                }
                if (empty($controlOptions['inline']))
                {
                    $controlOptions['inline'] = '1';
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

    /**
     * @param array $controlOptions
     * @param array $rowOptions
     *
     * @return string
     */
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

    /**
     * @param array $controlOptions
     * @param bool  $wrap
     *
     * @return mixed|string
     */
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
        $inline = $this->processAttributeToRaw($controlOptions, 'inline');
        $placeholder = $this->processAttributeToRaw($controlOptions, 'placeholder');
        $ariaLabel = $this->processAttributeToRaw($controlOptions, 'aria-label');

        return $this->renderMacro('public:svPasswordTools_macros', 'password_input' . ($wrap ? '_wrap' : ''), [
            'class' => $class,
            'xfInit' => $xfInit,
            'inputName' => $name,
            'password' => $password,
            'explain' => $explain,
            'label' => $label,
            'ariaLabel' => $ariaLabel,
            'required' => $required,
            'disabled' => $disabled,
            'autofocus' => $autofocus,
            'showPasswordStrength' => $showPasswordStrength,
            'inline' => $inline,
            'placeholder' => $placeholder,
            // unhandled attributes, maybe the template will do something with it?
            'controlOptions' => $controlOptions,
        ]);
    }
}