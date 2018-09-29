var SV = window.SV || {};
SV.PasswordTools = SV.PasswordTools || {};

!function($, window, document, _undefined)
{
    "use strict";

    SV.PasswordTools.PasswordToggler = XF.Element.newHandler({

        options: {
            showPasswordClass: 'inputPassword-button--show',
            hidePasswordClass: 'inputPassword-button--hide'
        },

        $passwordInput: null,
        $passwordToggler: null,
        isHidden: true,

        init: function()
        {
            this.$passwordInput = this.$target.find('[type="password"]');
            if (!this.$passwordInput.length)
            {
                console.error('No password input available.');
                return;
            }

            this.$passwordToggler = this.$target.find('.inputPassword-button');
            if (!this.$passwordToggler.length)
            {
                console.error('No password toggler available.');
                return;
            }

            this.$passwordToggler.on('click', XF.proxy(this, 'toggleShowVisibility'));

            if (this.isMobileDevice())
            {
                this.toggleShowVisibility();
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
        }
    });

    XF.Element.register('password-toggler', 'SV.PasswordTools.PasswordToggler');
}
(jQuery, window, document);