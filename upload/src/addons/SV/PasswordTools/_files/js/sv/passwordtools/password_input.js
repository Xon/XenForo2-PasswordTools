var SV = window.SV || {};
SV.PasswordTools = SV.PasswordTools || {};

!function($, window, document, _undefined)
{
    "use strict";

    SV.PasswordTools.PasswordInput = XF.Element.newHandler({

        options: {
            showPasswordClass: 'inputPassword-button--show',
            hidePasswordClass: 'inputPassword-button--hide',
            delta: 5,
            guessesReferanceTypes: {
                tooEasy: 1000,
                easy: 1000000,
                medium: 100000000,
                hard: 100000000
            },
            passwordStrengthClasses: {
                tooEasy: 'too-easy',
                easy: 'easy',
                medium: 'medium',
                hard: 'hard',
                brutal: 'brutal'
            },
        },

        $container: null,
        $passwordInput: null,
        $passwordStrengthBar: null,
        $passwordToggler: null,
        isHidden: true,

        init: function()
        {
            this.$container = this.$target;
            if (this.$container.is('input'))
            {
                this.$container = this.$container.parent();
                if (this.$container.hasClass('iconic--radio'))
                {
                    var radioButton = this.$container.find('input[type="radio"]');
                    if (radioButton.length)
                    {
                        radioButton = $('[name="' + radioButton.attr('name') + '"]');
                        radioButton.on('click', XF.proxy(this, 'toggleInputActiveState'));
                        this.$container = this.$container.parent();
                    }
                }
            }

            this.$passwordInput = this.$container.find('[type="password"]');
            if (!this.$passwordInput.length)
            {
                console.error('No password input available.');
                return;
            }

            this.$passwordStrengthBar = this.$container.find('.inputPassword-strength-bar');
            if (!this.$passwordStrengthBar)
            {
                console.log('Password strength bar missing.');
                return;
            }

            this.$passwordInput.on('input', XF.proxy(this, 'syncPasswordStrengthBar'));

            this.$passwordToggler = this.$container.find('.inputPassword-button');
            if (this.$passwordToggler.length)
            {
                this.$passwordToggler.on('click', XF.proxy(this, 'toggleShowVisibility'));

                if (this.isMobileDevice())
                {
                    this.toggleShowVisibility();
                }
            }
        },

        // TODO: Use XF.browser? What about touch screen labtops?
        isMobileDevice: function ()
        {
            try
            {
                document.createEvent("TouchEvent");
                return true;
            }
            catch (e)
            {
                return false;
            }
        },

        toggleInputActiveState: function(e)
        {
            if ($(e.target).val() === 'generate' && $(e.target).is(':checked'))
            {
                this.$passwordInput.prop('disabled', true);
                this.$passwordToggler.prop('disabled', true);
            }
            else
            {
                this.$passwordInput.prop('disabled', false);
                this.$passwordToggler.prop('disabled', false);
            }
        },
        
        toggleShowVisibility: function ()
        {
            var classToRemove = '',
                classToAdd = '',
                newInputType = '',
                tooltip = '';

            if (this.$passwordToggler.hasClass(this.options.showPasswordClass))
            {
                if (this.$passwordInput.attr('type') !== 'password')
                {
                    return;
                }

                newInputType = 'text';
                classToRemove = this.options.showPasswordClass;
                classToAdd = this.options.hidePasswordClass;
                tooltip = XF.phrase('svPasswordTools_hide_password');
            }
            else if (this.$passwordToggler.hasClass(this.options.hidePasswordClass))
            {
                if (this.$passwordInput.attr('type') !== 'text')
                {
                    return;
                }

                newInputType = 'password';
                classToRemove = this.options.hidePasswordClass;
                classToAdd = this.options.showPasswordClass;
                tooltip = XF.phrase('svPasswordTools_show_password');
            }
            else
            {
                console.error('Unknown password toggler')
            }

            this.$passwordInput.attr('type', newInputType);
            this.$passwordToggler
                .removeClass(classToRemove)
                .addClass(classToAdd)
                .attr('title', tooltip);
        },

        syncPasswordStrengthBar: function ()
        {
            if (typeof zxcvbn === "undefined")
            {
                console.error('Zxcvbn library missing');
                return;
            }

            var $password = this.$passwordInput.val();

            if ($password.length === 0)
            {
                this.updatePasswordStrengthBar('none');
                return;
            }

            var $result = zxcvbn($password, XF.config.passwordBlacklist),
                self = this,
                blacklisted = false;

            $.each($result.sequence, function (key, data)
            {
                if (data.dictionary_name === 'user_inputs')
                {
                    self.updatePasswordStrengthBar('none', XF.phrase('svPasswordTools_password_strength_type_blacklisted'));
                    blacklisted = true;
                }
            });

            if (blacklisted)
            {
                return;
            }

            if ($result.guesses < (this.options.guessesReferanceTypes.tooEasy + 5))
            {
                this.updatePasswordStrengthBar('too_easy');
            }
            else if ($result.guesses < (this.options.guessesReferanceTypes.easy + 5))
            {
                this.updatePasswordStrengthBar('easy');
            }
            else if ($result.guesses < (this.options.guessesReferanceTypes.medium + 5))
            {
                this.updatePasswordStrengthBar('medium');
            }
            else if ($result.guesses < (this.options.guessesReferanceTypes.hard + 5))
            {
                this.updatePasswordStrengthBar('hard');
            }
            else
            {
                this.updatePasswordStrengthBar('brutal');
            }
        },

        updatePasswordStrengthBar: function (type, text)
        {
            if (type === undefined)
            {
                console.error('Password strength type must be provided.');
                return;
            }

            var $replaceAll = false;
            if (text === undefined)
            {
                text = XF.phrase('svPasswordTools_password_strength_type_' + type);
            }

            this.$passwordStrengthBar.find('.inputPassword-strength-bar--value').text(text);
            if (type !== 'none')
            {
                this.$passwordStrengthBar.attr('class', 'inputPassword-strength-bar ' + type);
            }
            else
            {
                this.$passwordStrengthBar.attr('class', 'inputPassword-strength-bar');
            }
        }
    });

    XF.Element.register('password-input', 'SV.PasswordTools.PasswordInput');
}
(jQuery, window, document);