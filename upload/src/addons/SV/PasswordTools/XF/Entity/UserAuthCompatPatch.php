<?php /** @noinspection RedundantSuppression */

namespace SV\PasswordTools\XF\Entity;

if (\XF::$versionId < 2020000)
{
    /**
     * @extends \XF\Entity\UserAuth
     * @method bool svCheckPasswordOnSet(string $password, int $updatePasswordDate, \Closure $parentCallable)
     */
    class UserAuthCompatPatch extends XFCP_UserAuthCompatPatch
    {
        /**
         * @noinspection PhpMethodParametersCountMismatchInspection
         * @noinspection PhpSignatureMismatchDuringInheritanceInspection
         * @noinspection PhpMissingReturnTypeInspection
         * @noinspection PhpDocSignatureInspection
         * @noinspection PhpMissingParentCallCommonInspection
         */
        public function setPassword($password, $authClass = null, $updatePasswordDate = true)
        {
            return $this->svCheckPasswordOnSet($password, $updatePasswordDate, function () use ($password, $authClass, $updatePasswordDate) {
                return parent::setPassword($password, $authClass, $updatePasswordDate);
            });
        }
    }
}
else
{
    /**
     * @extends \XF\Entity\UserAuth
     * @method bool svCheckPasswordOnSet(string $password, int $updatePasswordDate, \Closure $parentCallable)
     */
    class UserAuthCompatPatch extends XFCP_UserAuthCompatPatch
    {
        /**
         * @noinspection PhpMethodParametersCountMismatchInspection
         * @noinspection PhpSignatureMismatchDuringInheritanceInspection
         * @noinspection PhpMissingReturnTypeInspection
         * @noinspection PhpDocSignatureInspection
         * @noinspection PhpMissingParentCallCommonInspection
         */
        public function setPassword($password, $authClass = null, $updatePasswordDate = true, $allowReuse = true)
        {
            return $this->svCheckPasswordOnSet($password, $updatePasswordDate, function () use ($password, $authClass, $updatePasswordDate, $allowReuse) {
                return parent::setPassword($password, $authClass, $updatePasswordDate, $allowReuse);
            });
        }
    }
}