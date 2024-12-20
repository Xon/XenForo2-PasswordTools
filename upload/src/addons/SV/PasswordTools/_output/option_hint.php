<?php

// ################## THIS IS A GENERATED FILE ##################
// DO NOT EDIT DIRECTLY. EDIT THE OPTIONS IN THE CONTROL PANEL.

/**
 * @noinspection PhpMultipleClassDeclarationsInspection
 * @noinspection PhpIllegalPsrClassPathInspection
 */

namespace XF;

/**
 * @property bool|null $svAlertOnCompromisedPasswordOnLogin On login; alert the user if they have a known compromised password
 * @property bool|null $svEnforcePasswordComplexityForAdmins Enforce password complexity for admins
 * @property bool|null $svOnLoginConsiderKnownBadAsCompromised On login; consider known-bad passwords as compromised
 * @property array|null $svPasswordStrengthMeter_blacklist Reject password fragments
 * @property bool|null $svPasswordStrengthMeter_blacklistFrontend Use rejected password fragments in password meter
 * @property bool|null $svPasswordStrengthMeter_force Force Reject
 * @property int|null $svPasswordStrengthMeter_min Minimum password length
 * @property int|null $svPasswordStrengthMeter_str Minimum password strength
 * @property array{length: bool, zxcvbn: bool, pwned: bool, known_bad: bool}|null $svPasswordToolsCheckTypes New password validation rules
 * @property int|null $svPwnedPasswordAlertRecurring Minimum time between triggering compromised password alerts on login
 * @property int|null $svPwnedPasswordCacheTime Pwned password cache time
 * @property bool|null $svPwnedPasswordForceEmail2FA Force email two factor authentication on compromised password
 * @property bool|null $svPwnedPasswordForcePasswordReset Force password reset on compromised password
 * @property non-negative-int|null $svPwnedPasswordGroup User-group for compromised passwords
 * @property int|null $svPwnedPasswordReuseCount Pwned password minimum count (hard)
 * @property int|null $svPwnedPasswordReuseCountSoft Pwned password minimum count (soft)
 * @property bool|null $svShowHidePassword Add show/hide password toggle
 */
class Options
{
}
