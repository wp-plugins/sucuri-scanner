=== Sucuri Security - Auditing, Malware Scanner and Hardening ===
Contributors: dd@sucuri.net
Donate Link: http://sitecheck.sucuri.net
Tags: malware, security, firewall, scan, spam, virus, sucuri, protection
Requires at least:3.2
Stable tag:1.6.8
Tested up to: 3.9.2

The Sucuri Security - Auditing, SiteCheck Malware Scanner and Hardening is a security plugin enables you to scan your WordPress site using Sucuri SiteCheck for security and malware issues, and also verifies the security integrity of your core files right in your dashboard. It includes audit trails and post-hack security ions to help you reset passwords and secret keys in case it has been already hacked, or infected with malware.

== Description ==

The Sucuri Security - Auditing, SiteCheck Malware Scanner and Hardening is a security plugin enables you to scan your WordPress site using Sucuri SiteCheck for security and malware issues, and also verifies the security integrity of your core files right in your dashboard. It includes audit trails and post-hack security ions to help you reset passwords and secret keys in case it has been already hacked, or infected with malware.

You can also run the checks for malware, blacklisting, and overall security status by scanning for free at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Sucuri SiteCheck detects various types of malware, SPAM injections, website errors, disabled sites, database connection issues and code anomalies that require special attention to include:

* Obfuscated JavaScript injections
* Cross Site Scripting (XSS)
* Website Defacements
* Hidden & Malicious iFrames
* PHP Mailers
* Phishing Attempts
* Malicious Redirects
* Anomalies
* Drive-by-Downloads
* IP Cloaking
* Social Engineering Attacks


There are a number of blacklisting authorities that monitor for malware, SPAM, and phishing attempts. Sucuri SiteCheck leverages the APIs for these authorities to check your website blacklisting status:

* Sucuri
* Google Safe Browsing
* Norton
* AVG
* Phish Tank (Phishing Specifically)
* ESET
* McAfee SiteAdvisor
* Yandex

We augment the SiteCheck Malware Scanner with various. 1-click hardening options. Some of these options do not provide a high level of security, but collectively these options do lower your risk floor:

* Verify WordPress Version
* Protect Uploads Directory
* Restrict wp-content Access
* Restrict wp-includes Access
* Verify PHP Version
* Disable the theme and plugin editors

On the newest versions of the plugin we also added an option to verify all WordPress core files for changes,
which can be useful to detect hidden backdoors.

Note that if your site is compromised and you need urgent help, you can leverage the 
Sucuri plans here: http://sucuri.net (even if our free options are not finding
the compromise on your site).


== Installation  ==

1. Download the plugin.
1. Go to the WordPress Plugin menu and activate it.
1. That's it!


== Changelog ==

= 1.6.8 =
* Fixing interface.

= 1.6.7 =
* Added Support for integrity checks on i18n installations.
* Fixed the setting change bug.

= 1.6.6 =
* Internal code cleanup and re-organization.
* More white lists for the integrity checks.
* Additional settings to customize some of the warnings.

= 1.6.5 =
* Fixed integrity checking display.

= 1.6.4 =
* Fixed API generation bug.

= 1.6.3 = 
* Added proper brute force alerts. 
* Added option to restrict number of emails. 
* Added more description to the emails. 
* Added a list of failed login attempts inside the last login tab. 

= 1.6.2 =
* Setting a maximum number of emails per hour.
* Fixing typos.


= 1.6.1 =
* Initial release with new auditing options.

= 1.6.0 =
* A new dashboard to welcome users to the new features of the plugin.
* Overall design of the interface of all the pages were modified.
* SiteCheck scanner results were filled with more information.
* SiteCheck scanner results markers when the site is infected/clean.
* System Info page were simplified with tabulation containers.
* Integrity check for administrator accounts was optimized.
* Integrity check for outdated plugins/themes was optimized and merged.
* IPv6 support in last logins statistics.


= 1.5.7 =
* WordPress 3.9 compatibility

= 1.5.6 =
* Added IPv6 support.
* Fixed links and messaging.

= 1.5.5 = 
* Added list of logged in users.
* Added system page.
* Change the integrity checking to use WP API.

= 1.5.4 = Bug fixes.

= 1.5.2 =
* Adding additional information about .htaccess hacks and the server environment.

= 1.5.0 =
* Fixing last login and giving better warns on permission errors.
* Making the integrity check messages more clear.

= 1.4.8 =
* New and clean design for the scan results.
* Adding a web firewall check on our hardening page.

= 1.4.7 =
* Cleaning up the code a bit. 
* Only displaying last login messages to admin users.
* Storing the logs into a log file instead of the db.

= 1.4.6 =
* Increasing last login table to the last 100 entries.

= 1.4.5 =
* Fixing some issues on the last login and allowing the option to disable it.

= 1.4.4 =
* Small bug fixes + forcing a re-scan on every scan attempt (not using the cache anymore).

= 1.4.3 =
* Fixing a few PHP warnings.

= 1.4.2 =
* Fixing a few PHP warnings.

= 1.4.1 =
* Small bug fixes.
* Adding last IP to the last login page.

= 1.4 =
* Added post-hack options (reset all passwords).
* Added last-login.
* Added more hardening and the option to revert any hardening done.

= 1.3 =
* Removed some PHP warnings and code clean up.
* Added WordPress integrity checks.
* Added plugin/theme/user checks.

= 1.2.2 =
* Tested on WP 3.5.1

= 1.2.1 =
* Tested on WP 3.5-RC4
* Style changes

= 1.2 =
* Cleared PHP warnings
* Added /inc directory
* Added /lib directory
* Logo added
* Default stylesheet added
* Header area added
* Sidebar area added
* Restyled 1-click hardening page
* Removed old malware page

= 1.1.7 =
 * Tested on WP 3.5-RC3.

= 1.1.6 =
 * Upgrading for WP 3.3.

= 1.1.5 =
 * Removed PHP warnings / code cleaning.

= 1.1.3 =
 * Cleaning up the results.
 * Added 1-click hardening.

= 1.1.2 =
 * First release that is good to be used (debugging code removed). 

= 1.1.1 = 
 * First public release. 

== Credits ==

 * <a href="http://sucuri.net">Sucuri Security</a>

