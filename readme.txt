=== WP Plugin Security Check ===
Contributors: ldebrouwer
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=HKVBMV9Q94PUL
Tags: WordPress, plugin, security, check
Requires at least: 3.1
Tested up to: 3.1.1
Stable tag: 0.4

WP Plugin Security Check checks if your WordPress plugins are 'safe'.

== Description ==

An up-to-date WordPress installation is as safe as it can be, plugins however can often pose a security risk because they're not maintained by hundreds of contributors. A plugin is as secure as the security knowledge of the developer allows it to be. In some cases this creates loopholes for exploits. WP Plugin Security Check checks plugins for bad practices and possible security holes limiting the risk of a compromised WordPress installation to a 'hate to say I told you so'.

== Installation ==

1. Upload the folder `wp-plugin-security-check` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. You're all done.

== Frequently Asked Questions ==

= What does it do? =

WP Plugin Security Check checks whether your WordPress plugins are safe. It aims to detect certain bad practices which might expose your WordPress installation to known security risks.

== Screenshots ==

1. The WP Plugin Security Check page.

== Changelog ==

= 0.4 =
* Added support for detecting javascript in the plugin headers.
* Squashed a minor bug. Thanks to Julio Potier.

= 0.3 =
* Added another way to check for image files to reduce the number of false positives.

= 0.2 =
* Included checks for variable execution and the PHP function eval.

= 0.1 =
* First version of the plugin.

== Upgrade Notice ==