<?php
/*
 * Plugin Name: WP Plugin Security Check
 * Plugin URI: http://www.lucdebrouwer.nl/wordpress-plugin-wp-plugin-security-check/
 * Description: WP Plugin Security Check checks if your WordPress plugins are 'safe'.
 * Version: 0.4
 * Author: Luc De Brouwer
 * Author URI: http://www.lucdebrouwer.nl/
 *
 */

add_action( 'admin_menu', 'LDB_wp_plugin_security_check_menu' );

function LDB_wp_plugin_security_check_menu() {
	add_plugins_page( 'WP Plugin Security Check', 'Security Check', 'activate_plugins', 'wp_plugin_security_check', 'LDB_wp_plugin_security_check_page' );
}

function LDB_wp_plugin_security_check_request_uri( $content ) {
	$regexp = '/\$_SERVER\[[\'"]REQUEST_URI[\'"]\]/';
	if( preg_match_all( $regexp, $content, $matches ) ) {
		return true;
	} else {
		return false;
	}
}

function LDB_wp_plugin_security_check_get_ext( $name ) {
	$parts = explode( '.', $name );
	return strtolower( $parts[( count( $parts )-1 )] );
}

function LDB_wp_plugin_security_check_variable_execution( $content ) {
	$regexp = '/\$([a-zA-Z0-9-_]+)\(/';
	if( preg_match_all( $regexp, $content, $matches ) ) {
		return true;
	} else {
		return false;
	}
}

function LDB_wp_plugin_security_check_evaluation( $content ) {
	$regexp = '/eval\(([^\)]*)\)/';
	if( preg_match_all( $regexp, $content, $matches ) ) {
		return true;
	} else {
		return false;
	}
}

function LDB_wp_plugin_security_check_data( $plugin ) {
	$hit = false;
	foreach( $plugin as $key => $value ){
		$regexp = '/<script/';
		if( preg_match_all( $regexp, strtolower( $value ), $matches ) ) {
			$hit = true;
		}
	}
	return $hit;
}

function LDB_wp_plugin_security_check( $file ) {
	$hits = array();
	$realfile = WP_PLUGIN_DIR . '/' . $file;
	if( file_exists( $realfile ) ){
		$image = false;
		// Check if finfo_file() is supported;
		if( function_exists( 'finfo_file' ) && function_exists( 'finfo_open' ) ){
			$mime_type = explode( '/', finfo_file( finfo_open( FILEINFO_MIME_TYPE ), $realfile ) );
			if ($mime_type[0] === 'image') {
				$image = true;
			}
		} else if ( function_exists( 'mime_content_type' ) ) {
			$mime_type = explode( '/', mime_content_type( $realfile ) );
			if ($mime_type[0] === 'image') {
				$image = true;
			}
		} else if ( LDB_wp_plugin_security_check_get_ext( $realfile ) == 'png' || LDB_wp_plugin_security_check_get_ext( $realfile ) == 'jpg' || LDB_wp_plugin_security_check_get_ext( $realfile ) == 'jpeg' || LDB_wp_plugin_security_check_get_ext( $realfile ) == 'gif'){
			$image = true;
		}
		// Don't scan images for now.
		if( !$image ) {
			$content = file_get_contents( $realfile );
			$request_uri_test = LDB_wp_plugin_security_check_request_uri( $content );
			if( $request_uri_test ){
				$hits[] = array('$_SERVER[\'REQUEST_URI\'] detected in ' . $file, 'notice');
			}
			$eval_test = LDB_wp_plugin_security_check_evaluation( $content );
			if( $eval_test ){
				$hits[] = array('eval&#40;&#41; detected in ' . $file, 'warning');
			}
			$var_exec_test = LDB_wp_plugin_security_check_variable_execution($content);
			if( $var_exec_test ){
				$hits[] = array('Variable execution detected in ' . $file, 'warning');
			}
			if( count( $hits ) > 0 ){
				return $hits;
			} else {
				return false;
			}
		} else {
			return false;
		}
	} else {
		return false;
	}
}

function LDB_wp_plugin_security_check_page() {
?>
	<style>
		.inside p {
			margin: 10px;
		}
		.wp_plugin_security_check_plugin {
			margin: 5px;
			background: #eff5ea;
			border: 1px solid green;
			padding: 0 5px;
			border-radius: 3px;
		}
		.wp_plugin_security_check_plugin.unsafe {
			background: #ffbebe;
			border: 1px solid red;
		}
		.wp_plugin_security_check_plugin.notice {
			background: #ffffe0;
			border: 1px solid #e6db55;
		}
		.wp_plugin_security_check ul li {
			list-style: square;
			margin-left: 20px;
		}
		.wp_plugin_security_check .donate {
			width: 25%;
			float: right;
			border-color: green;
			border-width: 2px;
		}
		.wp_plugin_security_check .about {
			width: 25%;
			float: right;
		}
		.wp_plugin_security_check .donate .hndle {
			color: green;
			font-weight: bold;
			font-size: 105%;
		}
		.wp_plugin_security_check .check {
			width: 70%;
			float: left;
		}
		.wp_plugin_security_check h2 {
			margin: 0 0 10px;
		}
	</style>
	<div class="wrap meta metabox-holder wp_plugin_security_check">
		<div id="icon-plugins" class="icon32">
			<br />
		</div>
		<h2>WP Plugin Security Check</h2>
		<div class="postbox check">
			<h3 class="hndle"><span>Plugins</span></h3>
			<div class="inside">
				<p>WP Plugin Security Check checks your WordPress plugins for bad practices and possible security holes.</p>
<?php
$plugins = get_plugins();
$plugins_keys = array_keys( get_plugins() );
for( $p = 0, $pc = count( $plugins ); $p < $pc; $p++ ) {
	$hitlist = array();
	$plugin_files = get_plugin_files( $plugins_keys[$p] );
	$safe = true;
	$class = 'safe';
	$data_hit = LDB_wp_plugin_security_check_data( $plugins[$plugins_keys[$p]] );
	if( $data_hit ) {
		$class = 'unsafe';
		$hitlist[] = array( array('Javascript detected in plugin headers', 'warning') );
	}
	for( $f = 0, $fc = count( $plugin_files ); $f < $fc; $f++ ){
		$hit = LDB_wp_plugin_security_check( $plugin_files[$f] );
		if( $hit ){
			$hitlist[] = $hit;
			$safe = false;
			if( $class !== 'unsafe') {
				$class = 'notice';
				for( $h = 0, $hc = count( $hit ); $h < $hc; $h++ ) {
					if( $hit[$h][1] === 'warning' ) {
						$class = 'unsafe';
					}
				}
			}
		}
	}
?>
				<div class="wp_plugin_security_check_plugin <?php if( $safe ){ echo $class; } else { echo $class; }?>">
					<h4><?php echo esc_attr($plugins[$plugins_keys[$p]]['Name']); ?></h4>
<?php
	if( count( $hitlist ) > 0 ){
?>
					<ul>
<?php
		for( $h = 0, $hc = count($hitlist); $h < $hc; $h++ ){
			foreach( $hitlist[$h] as $key => $value ){
?>
						<li><?php echo $value[0]; ?></li>
<?php
			}
		}
?>
					</ul>
<?php
	}
?>
				</div>
<?php
}
?>
			</div>
		</div>
		<div class="postbox donate">
			<h3 class="hndle"><span>Please donate</span></h3>
			<form action="https://www.paypal.com/cgi-bin/webscr" method="post">
				<input type="hidden" name="cmd" value="_s-xclick">
				<input type="hidden" name="hosted_button_id" value="HKVBMV9Q94PUL">
				<img alt="" border="0" src="https://www.paypal.com/nl_NL/i/scr/pixel.gif" width="1" height="1">
				<table class="form-table" cellpadding="0" cellspacing="0" border="0">
					<tr>
						<td>
							<p>A lot of time and effort went into making this plugin and much more will be invested in it. A donation is very much appreciated, thank you.</p>
							<p style="text-align: center;"><input type="image" src="https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!"></p>
						</td>
					</tr>
				</table>
			</form>
		</div>
		<div class="postbox about">
			<h3 class="hndle"><span>About WP Plugin Security Check</span></h3>
			<div class="inside">
				<p>The reason why WP Plugin Security Check was created was Andrew Nacin's and Mark Jaquith's keynote at WordCamp Miami 2011. During this keynote they mentioned that most of the risks a WordPress installation faces are caused by badly written plugins. WP Plugin Security tries to detect the bad practices and most common mistakes made by plugin developers. Of course this is almost impossible to fully check and therefor I'd like to add that it's more like an early warning system.</p>
				<p>Currently the plugin checks the following:</p>
				<ul>
					<li>Usage of $_SERVER[&#39;REQUEST_URI&#39] ( which could open your site to <a href="http://en.wikipedia.org/wiki/Cross-site_request_forgery" target="_blank">CSRF</a> attacks ). However some plugins require this, especially those who facilitate 301 redirects.</li>
					<li>Usage of the eval&#40;&#41; PHP function which allows users to interpret a string as PHP code</li>
					<li>Variable execution. Although this is somewhat common it's also a trick often used to prevent easy detection of malicious code as pointed out in this <a href="http://ottopress.com/2011/scanning-for-malicious-code-is-pointless/" target="_blank">excellent post</a> by Samuel Wood.</li>
				</ul>
<?php
	if ( !function_exists( 'finfo_file' ) && !function_exists( 'mime_content_type' ) ) {
?>
				<p><strong>Notice :</strong> Your hosting currently doesn't support the PHP functions <a href="http://php.net/manual/en/function.finfo-file.php" target="_blank">finfo_file</a> or <a href="http://php.net/manual/en/function.mime-content-type.php" target="_blank">mime_content_type</a> which means that image files have been excluded from testing based on their extension. This isn't fullproof but limits the number of false positives for variable execution.</p>
<?php
	}
?>
			</div>
		</div>
	</div>
<?php
}