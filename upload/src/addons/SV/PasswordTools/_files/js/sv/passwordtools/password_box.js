!function()
{
    "use strict";

    XF.Element.extend('password-strength', {
        __backup: {
            init: 'superInit',
            input: 'superInput',
        },

        init: function()
        {
            this.svPasswordToolsRejectFragments = null;

            this.superInit();

            var fragmentElements = document.getElementsByClassName('js-svPasswordToolsRejectFragments');

            if (!fragmentElements.length)
            {
                return;
            }

            var data = JSON.parse(fragmentElements[0].innerHTML);
            var rejectFragments = [];

            for (var key in data.fragmentSets)
            {
                if (data.fragmentSets.hasOwnProperty(key) && data.fragmentSets[key].length)
                {
                    rejectFragments = rejectFragments.concat(data.fragmentSets[key]);
                }
            }

            this.svPasswordToolsRejectFragments = rejectFragments.length ? rejectFragments : null;
            this.svPasswordToolsForceReject = data.forceReject;
        },

        input: function()
        {
            if (!this.svPasswordToolsRejectFragments)
            {
                this.superInput();
                return;
            }

            var password = this.$password.val(),
                result = zxcvbn(password, this.svPasswordToolsRejectFragments || []),
                score = result.score,
                value,
                message = result.feedback.warning || '',
                messageExtra = null;

            // note: the messages in this file are translated elsewhere


            if (password === '')
            {
                message = 'Entering a password is required';
                value = 0;
            }
            else
            {
                if (this.svPasswordToolsForceReject)
                {
                    var matchedWords = [];

                    for (var i = 0; i < result.sequence.length; i++)
                    {
                        var item = result.sequence[i];
                        if (item.pattern === 'dictionary' && item.dictionary_name === 'user_inputs')
                        {
                            matchedWords.push(item.token);

                            if (item.token.toLowerCase() !== item.matched_word.toLowerCase())
                            {
                                matchedWords.push(item.matched_word);
                            }
                        }
                    }

                    if (matchedWords.length)
                    {
                        message = "Your password can't contain any variation of the following phrase(s):";
                        score = 0;
                        messageExtra = matchedWords.join(", ");
                    }
                }

                value = (score + 1) * 20;

                if (score >= 4)
                {
                    message = 'This is a very strong password';
                }
                else if (score >= 3)
                {
                    message = 'This is a reasonably strong password';
                }
                else if (!message)
                {
                    message = 'The chosen password could be stronger';
                }
            }

            message = this.language[message] || message;

            if (messageExtra !== null)
            {
                message += ' ' + messageExtra;
            }

            this.$meter.val(value);
            this.$meterText.text(message);
        },
    });
}();
