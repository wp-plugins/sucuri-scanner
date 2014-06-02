<?php
/*
Plugin Name: Sucuri Security - SiteCheck Malware Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: The <a href="http://sucuri.net">Sucuri Security</a> - SiteCheck Malware Scanner plugin enables you to <strong>scan your WordPress site using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a></strong> right in your WordPress dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.

You can also scan your site at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Author: Sucuri, INC
Version: 1.5.7
Author URI: http://sucuri.net
*/


/**
 * Main file to control the plugin.
 *
 * @package   Sucuri Plugin - SiteCheck Malware Scanner
 * @author    Yorman Arias <yorman.arias@sucuri.net>
 * @author    Daniel Cid   <dcid@sucuri.net>
 * @copyright Since 2010 Sucuri Inc.
 * @license   Released under the GPL - see LICENSE file for details.
 * @link      https://wordpress.sucuri.net/
 * @since     File available since Release 0.1
 */


/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

/**
 * Unique name of the plugin through out all the code.
 */
define('SUCURISCAN','sucuriscan');

/**
 * Current version of the plugin's code.
 */
define('SUCURISCAN_VERSION','1.5.7');

/**
 * The local URL where the plugin's files and assets are served.
 */
define('SUCURI_URL', rtrim(plugin_dir_url( __FILE__ ),'/') );

/**
 * The name of the Sucuri plugin main file.
 */
define('SUCURISCAN_PLUGIN_FILE', 'sucuri.php');

/**
 * The name of the folder where the plugin's files will be located.
 */
define('SUCURISCAN_PLUGIN_FOLDER', 'sucuri-scanner');

/**
 * The fullpath where the plugin's files will be located.
 */
define('SUCURISCAN_PLUGIN_PATH', WP_PLUGIN_DIR.'/'.SUCURISCAN_PLUGIN_FOLDER);

/**
 * The fullpath of the main plugin file.
 */
define('SUCURISCAN_PLUGIN_FILEPATH', SUCURISCAN_PLUGIN_PATH.'/'.SUCURISCAN_PLUGIN_FILE);

/**
 * The maximum quantity of entries that will be displayed in the last login page.
 */
define('SUCURISCAN_LASTLOGINS_USERSLIMIT', 50);

if( !function_exists('sucuriscan_create_uploaddir') ){
    /**
     * Create a folder in the WordPress upload directory where the plugin will
     * store all the temporal or dynamic information.
     *
     * @return void
     */
    function sucuriscan_create_uploaddir(){
        $plugin_upload_folder = sucuriscan_dir_filepath();
        if( !file_exists($plugin_upload_folder) ){
            if( @mkdir($plugin_upload_folder) ){
                sucuriscan_lastlogins_datastore_exists();
            }else{
                sucuriscan_admin_notice('error', "<strong>Error.</strong> Sucuri data folder doesn't
                    exists and couldn't be created. You'll need to create this folder manually and
                    give it write permissions:<br><code>{$plugin_upload_folder}</code>");
            }
        }
    }

    add_action('admin_init', 'sucuriscan_create_uploaddir');
}

/**
 * Define which javascript and css files will be loaded in the header of the page.
 * @return void
 */
function sucuriscan_admin_script_style_registration() { ?>
    <link rel="stylesheet" href="<?php echo SUCURI_URL; ?>/inc/css/sucuriscan-default-css.css" type="text/css" media="all" />
    <script type="text/javascript">
    function sucuriscan_alert_close(id){
        var element = document.getElementById('sucuri-alert-'+id);
        element.parentNode.removeChild(element);
    }
    </script>
<?php }
add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );

/**
 * Returns the system filepath to the relevant user uploads directory for this
 * site. This is a multisite capable function.
 *
 * @param  string $path The relative path that needs to be completed to get the absolute path.
 * @return string       The full filesystem path including the directory specified.
 */
function sucuriscan_dir_filepath($path = '')
{
    $wp_dir_array = wp_upload_dir();
    $wp_dir_array['basedir'] = untrailingslashit($wp_dir_array['basedir']);
    return($wp_dir_array['basedir']."/sucuri/$path");
}

/**
 * Generate the menu and submenus for the plugin in the admin interface.
 *
 * @return void
 */
function sucuriscan_menu()
{
    add_menu_page('Sucuri Free', 'Sucuri Free', 'manage_options',
                  'sucuriscan', 'sucuri_scan_page', SUCURI_URL.'/inc/images/menu-icon.png');
    add_submenu_page('sucuriscan', 'Sucuri Scanner', 'Sucuri Scanner', 'manage_options',
                     'sucuriscan', 'sucuri_scan_page');

    add_submenu_page('sucuriscan', '1-Click Hardening', '1-Click Hardening', 'manage_options',
                     'sucuriscan_hardening', 'sucuriscan_hardening_page');

    add_submenu_page('sucuriscan', 'WordPress Integrity', 'WordPress Integrity', 'manage_options',
                     'sucuriscan_core_integrity', 'sucuriscan_core_integrity_page');

    add_submenu_page('sucuriscan', 'Post-Hack', 'Post-Hack', 'manage_options',
                     'sucuriscan_posthack', 'sucuriscan_posthack_page');

    add_submenu_page('sucuriscan', 'Last Logins', 'Last Logins', 'manage_options',
                     'sucuriscan_lastlogins', 'sucuriscan_lastlogins_page');

    add_submenu_page('sucuriscan', 'Site Info', 'Site Info', 'manage_options',
                     'sucuriscan_infosys', 'sucuriscan_infosys_page');

    add_submenu_page('sucuriscan', 'About', 'About', 'manage_options',
                     'sucuriscan_about', 'sucuriscan_about_page');
}

add_action('admin_menu', 'sucuriscan_menu');
remove_action('wp_head', 'wp_generator');

/**
 * Print the HTML code for the header of each plugin's page.
 *
 * @param  string $sucuri_title Title of the page that will be loaded.
 * @return void
 */
function sucuriscan_pagestop($sucuri_title = 'Sucuri Plugin')
{
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Header') );
    }
    ?>
    <h2><?php echo htmlspecialchars($sucuri_title); ?></h2>
    <br class="clear"/>
    <?php
}

/**
 * Send a message to a specific email address.
 *
 * @param  string  $to       The email address of the recipient that will receive the message.
 * @param  string  $subject  The reason of the message that will be sent.
 * @param  string  $message  Body of the message that will be sent.
 * @param  array   $data_set Optional parameter to add more information to the notification.
 * @param  boolean $debug    TRUE if you want to test the function printing the email before sending it.
 * @return void
 */
function sucuriscan_send_mail($to='', $subject='', $message='', $data_set=array(), $debug=FALSE)
{
    $headers = array();
    $subject = ucwords(strtolower($subject));
    $wp_domain = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : get_option('siteurl');
    if( get_option('sucuri_wp_prettify_mails')!='disabled' ){
        $headers = array( 'Content-type: text/html' );
        $data_set['PrettifyType'] = 'html';
    }
    $message = sucuriscan_prettify_mail($subject, $message, $data_set);

    if($debug){
        die($message);
    }else{
        wp_mail($to, "Sucuri WP Notification: {$wp_domain} - {$subject}" , $message, $headers);
    }
}

/**
 * Prints a HTML alert in the WordPress admin interface.
 *
 * @param  string $type    The type of alert, it can be either Updated or Error.
 * @param  string $message The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_admin_notice($type='updated', $message='')
{
    $alert_id = rand(100, 999);
    if( !empty($message) ): ?>
        <div id="sucuri-alert-<?php echo $alert_id; ?>" class="<?php echo $type; ?> sucuri-alert sucuri-alert-<?php echo $type; ?>">
            <a href="javascript:void(0)" class="close" onclick="sucuriscan_alert_close('<?php echo $alert_id; ?>')">&times;</a>
            <p><?php _e($message); ?></p>
        </div>
    <?php endif;
}

/**
 * Generate a HTML version of the message that will be sent through an email.
 *
 * @param  string $subject  The reason of the message that will be sent.
 * @param  string $message  Body of the message that will be sent.
 * @param  array  $data_set Optional parameter to add more information to the notification.
 * @return string           The message formatted in a HTML template.
 */
function sucuriscan_prettify_mail($subject='', $message='', $data_set=array())
{
    $current_user = wp_get_current_user();

    $prettify_type = isset($data_set['PrettifyType']) ? $data_set['PrettifyType'] : 'txt';
    $real_ip = isset($_SERVER['SUCURI_RIP']) ? $_SERVER['SUCURI_RIP'] : $_SERVER['REMOTE_ADDR'];

    $mail_variables = array(
        'TemplateTitle'=>'Sucuri WP Notification',
        'Subject'=>$subject,
        'Website'=>get_option('siteurl'),
        'RemoteAddress'=>$real_ip,
        'Message'=>$message,
        'User'=>$current_user->display_name,
        'Time'=>current_time('mysql')
    );
    foreach($data_set as $var_key=>$var_value){
        $mail_variables[$var_key] = $var_value;
    }

    return sucuriscan_get_template("notification.{$prettify_type}.tpl", $mail_variables);
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string  $template Filename of the template that will be used to generate the page.
 * @param  array   $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @param  boolean $type     Either page, section or snippet indicating the type of template that will be retrieved.
 * @return string            The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_template($template='', $params=array(), $type='page'){
    switch( $type ){
        case 'page': /* no_break */
        case 'section':
            $template_path_pattern = '%s/%s/inc/tpl/%s.html.tpl';
            break;
        case 'snippet':
            $template_path_pattern = '%s/%s/inc/tpl/%s.snippet.tpl';
            break;
    }

    $template_content = '';
    $template_path =  sprintf( $template_path_pattern, WP_PLUGIN_DIR, SUCURISCAN_PLUGIN_FOLDER, $template );
    $params = is_array($params) ? $params : array();

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);

        $current_page = isset($_GET['page']) ? htmlentities($_GET['page']) : '';
        $params['CurrentURL'] = sprintf( '%s/wp-admin/admin.php?page=%s', site_url(), $current_page );
        $params['SucuriURL'] = SUCURI_URL;
        $params['PageNonce'] = wp_create_nonce('sucuri_page_nonce');

        foreach($params as $tpl_key=>$tpl_value){
            $template_content = str_replace("%%SUCURI.{$tpl_key}%%", $tpl_value, $template_content);
        }
    }

    if( $template == 'base' || $type != 'page' ){
        return $template_content;
    } else {
        return sucuriscan_get_template('base', array(
            'PageContent' => $template_content,
            'PageStyleClass' => $template,
            'URL.Hardening' => sucuriscan_get_url('hardening'),
            'URL.CoreIntegrity' => sucuriscan_get_url('core_integrity'),
            'URL.PostHack' => sucuriscan_get_url('posthack'),
            'URL.LastLogins' => sucuriscan_get_url('lastlogins'),
        ));
    }
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template Filename of the template that will be used to generate the page.
 * @param  array  $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string           The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_section($template='', $params=array()){
    return sucuriscan_get_template( $template, $params, 'section' );
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template Filename of the template that will be used to generate the page.
 * @param  array  $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string           The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_snippet($template='', $params=array()){
    return sucuriscan_get_template( $template, $params, 'snippet' );
}

/**
 * Generate an URL pointing to the page indicated in the function and that must
 * be loaded through the administrator panel.
 *
 * @param  string $page Short name of the page that will be generated.
 * @return string       Full string containing the link of the page.
 */
function sucuriscan_get_url($page=''){
    if( !empty($page) ){
        $url_path = sprintf('%s?page=sucuriscan_%s', admin_url('admin.php'), $page);
        return $url_path;
    }

    return null;
}

/**
 * Retrieve a new set of keys for the WordPress configuration file using the
 * official API provided by WordPress itself.
 *
 * @return array A list of the new set of keys generated by WordPress API.
 */
function sucuriscan_get_new_config_keys()
{
    $request = wp_remote_get('https://api.wordpress.org/secret-key/1.1/salt/');
    if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
        if( preg_match_all("/define\('([A-Z_]+)',[ ]+'(.*)'\);/", $request['body'], $match) ){
            $new_keys = array();
            foreach($match[1] as $i=>$value){
                $new_keys[$value] = $match[2][$i];
            }
            return $new_keys;
        }
    }
    return FALSE;
}

/**
 * Modify the WordPress configuration file and change the keys that were defined
 * by a new random-generated list of keys retrieved from the official WordPress
 * API. The result of the operation will be either FALSE in case of error, or an
 * array containing multiple indexes explaining the modification, among them you
 * will find the old and new keys.
 *
 * @return false|array Either FALSE in case of error, or an array with the old and new keys.
 */
function sucuriscan_set_new_config_keys()
{
    $new_wpconfig = '';
    $wp_config_path = ABSPATH.'wp-config.php';

    if( file_exists($wp_config_path) ){
        $wp_config_lines = file($wp_config_path);
        $new_keys = sucuriscan_get_new_config_keys();
        $old_keys = array();
        $old_keys_string = $new_keys_string = '';

        foreach($wp_config_lines as $wp_config_line){
            $wp_config_line = str_replace("\n", '', $wp_config_line);

            if( preg_match("/define\('([A-Z_]+)',([ ]+)'(.*)'\);/", $wp_config_line, $match) ){
                $key_name = $match[1];
                if( array_key_exists($key_name, $new_keys) ){
                    $white_spaces = $match[2];
                    $old_keys[$key_name] = $match[3];
                    $wp_config_line = "define('{$key_name}',{$white_spaces}'{$new_keys[$key_name]}');";

                    $old_keys_string .= "define('{$key_name}',{$white_spaces}'{$old_keys[$key_name]}');\n";
                    $new_keys_string .= "{$wp_config_line}\n";
                }
            }

            $new_wpconfig .= "{$wp_config_line}\n";
        }

        $response = array(
            'updated'=>is_writable($wp_config_path),
            'old_keys'=>$old_keys,
            'old_keys_string'=>$old_keys_string,
            'new_keys'=>$new_keys,
            'new_keys_string'=>$new_keys_string,
            'new_wpconfig'=>$new_wpconfig
        );
        if( $response['updated'] ){
            file_put_contents($wp_config_path, $new_wpconfig, LOCK_EX);
        }
        return $response;
    }
    return FALSE;
}

/**
 * Generate and set a new password for a specific user not in session.
 *
 * @param  integer $user_id The user identifier that will be changed, this must be different than the user in session.
 * @return boolean          Either TRUE or FALSE in case of success or error respectively.
 */
function sucuriscan_new_password($user_id=0)
{
    $user_id = intval($user_id);
    $current_user = wp_get_current_user();

    if( $user_id>0 && $user_id!=$current_user->ID ){
        $user = get_userdata($user_id);
        $new_password = wp_generate_password(15, TRUE, FALSE);

        $data_set = array( 'User'=>$user->display_name );
        $message = "The password for your user account in the website mentioned has been changed by an administrator,
            this is the new password automatically generated by the system, please update ASAP.<br>
            <div style='display:inline-block;background:#ddd;font-family:monaco,monospace,courier;
            font-size:30px;margin:0;padding:15px;border:1px solid #999'>{$new_password}</div>";
        sucuriscan_send_mail($user->user_email, 'Changed password', $message, $data_set);

        wp_set_password($new_password, $user_id);

        return TRUE;
    }
    return FALSE;
}

/**
 * Retrieve the real ip address of the user in the current request.
 *
 * @return string The real ip address of the user in the current request.
 */
function sucuriscan_get_remoteaddr()
{
    $alternatives = array(
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR',
        'SUCURI_RIP',
    );
    foreach($alternatives as $alternative){
        if( !isset($_SERVER[$alternative]) ){ continue; }

        $remote_addr = preg_replace('/[^0-9a-z.,: ]/', '', $_SERVER[$alternative]);
        if($remote_addr) break;
    }

    return $remote_addr;
}

/**
 * Check whether the site is behing the Sucuri CloudProxy network.
 *
 * @return boolean Either TRUE or FALSE if the site is behind CloudProxy.
 */
function sucuriscan_is_behind_cloudproxy(){
    $http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    if( preg_match('/^(.*):([0-9]+)/', $http_host, $match) ){ $http_host = $match[1]; }
    $host_by_name = gethostbyname($http_host);
    $host_by_addr = gethostbyaddr($host_by_name);

    if(
        isset($_SERVER['SUCURIREAL_REMOTE_ADDR'])
        || preg_match('/^cloudproxy([0-9]+)\.sucuri\.net$/', $host_by_addr)
    ){
        return TRUE;
    }

    return FALSE;
}

/**
 * Check whether the current site is working as a multi-site instance.
 *
 * @return boolean Either TRUE or FALSE in case WordPress is being used as a multi-site instance.
 */
function sucuriscan_is_multisite(){
    if( function_exists('is_multisite') && is_multisite() ){ return TRUE; }
    return FALSE;
}

/**
 * Find and retrieve the absolute path of the WordPress configuration file.
 *
 * @return string Absolute path of the WordPress configuration file.
 */
function sucuriscan_get_wpconfig_path(){
    $wp_config_path = ABSPATH.'wp-config.php';

    // if wp-config.php doesn't exist/not readable check one directory up
    if( !is_readable($wp_config_path)){
        $wp_config_path = ABSPATH.'/../wp-config.php';
    }
    return $wp_config_path;
}

/**
 * Find and retrieve the absolute path of the main WordPress htaccess file.
 *
 * @return string Absolute path of the main WordPress htaccess file.
 */
function sucuriscan_get_htaccess_path(){
    $base_dirs = array(
        rtrim(ABSPATH, '/'),
        dirname(ABSPATH),
        dirname(dirname(ABSPATH))
    );

    foreach($base_dirs as $base_dir){
        $htaccess_path = sprintf('%s/.htaccess', $base_dir);
        if( file_exists($htaccess_path) ){
            return $htaccess_path;
        }
    }

    return FALSE;
}

/**
 * Return the time passed since the specified timestamp until now.
 *
 * @param  integer $timestamp The Unix time number of the date/time before now.
 * @return string             The time passed since the timestamp specified.
 */
function sucuriscan_time_ago($timestamp=0){
    if( !is_numeric($timestamp) ){
        $timestamp = strtotime($timestamp);
    }

    $diff = time() - (int)$timestamp;

    if( $diff == 0 ){ return 'just now'; }

    $intervals = array(
        1                => array('year',   31556926),
        $diff < 31556926 => array('month',  2628000),
        $diff < 2629744  => array('week',   604800),
        $diff < 604800   => array('day',    86400),
        $diff < 86400    => array('hour',   3600),
        $diff < 3600     => array('minute', 60),
        $diff < 60       => array('second', 1)
    );

    $value = floor($diff/$intervals[1][1]);
    return $value.chr(32).$intervals[1][0].($value > 1 ? 's' : '').' ago';
}

/**
 * Print a HTML code with a form from where the administrator can check the state
 * of this site through Sucuri SiteCheck.
 *
 * @return void
 */
function sucuri_scan_page(){
    $U_ERROR = NULL;
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Malware Scanner') );
    }

    if( isset($_POST['wpsucuri-doscan']) ){
        sucuriscan_print_scan();
        return(1);
    }

    echo sucuriscan_get_template('initial-page');
}

/**
 * Display the result of site scan made through SiteCheck.
 *
 * @return void
 */
function sucuriscan_print_scan(){
    $website_scanned = home_url();
    $remote_url = 'http://sitecheck.sucuri.net/scanner/?serialized&clear&fromwp&scan='.$website_scanned;
    $scan_results = wp_remote_get($remote_url, array('timeout' => 180));
    ob_start();
    ?>


    <?php if( is_wp_error($scan_results) ): ?>

        <div id="poststuff">
            <div class="postbox">
                <h3>Error retrieving the scan report</h3>
                <div class="inside">
                    <pre><?php print_r($scan_results); ?></pre>
                </div>
            </div>
        </div>

    <?php elseif( preg_match('/^ERROR:/', $scan_results['body']) ): ?>

        <?php sucuriscan_admin_notice('error', $scan_results['body'].' The URL scanned was: <code>'.$website_scanned.'</code>'); ?>

    <?php else: ?>

        <?php
        $res = @unserialize($scan_results['body']);

        // Check for general warnings, and return the information for Infected/Clean site.
        $malware_warns_exists   = isset($res['MALWARE']['WARN'])   ? TRUE : FALSE;
        $blacklist_warns_exists = isset($res['BLACKLIST']['WARN']) ? TRUE : FALSE;

        // Check whether this WordPress installation needs an update.
        global $wp_version;
        $wordpress_updated = FALSE;
        $updates = function_exists('get_core_updates') ? get_core_updates() : array();

        if( !is_array($updates) || empty($updates) || $updates[0]->response=='latest' ){
            $wordpress_updated = TRUE;
        }

        // Generate the CSS classes for the boxes.
        $sucuriscan_css_malware   = $malware_warns_exists   ? 'sucuriscan-border-bad'  : 'sucuriscan-border-good';
        $sucuriscan_css_blacklist = $blacklist_warns_exists ? 'sucuriscan-border-bad'  : 'sucuriscan-border-good';
        $sucuriscan_css_wpupdate  = $wordpress_updated      ? 'sucuriscan-border-good' : 'sucuriscan-border-bad' ;
        ?>

        <div id="poststuff">
            <div class="postbox sucuriscan-border <?php _e($sucuriscan_css_malware) ?>">
                <h3>
                    <?php if( $malware_warns_exists ): ?>
                        Site compromised (malware was identified)
                    <?php else: ?>
                        Site clean (no malware was identified)
                    <?php endif; ?>
                </h3>

                <div class="inside">

                    <?php if( !$malware_warns_exists ): ?>
                        <span><strong>Malware:</strong> No.</span><br>
                        <span><strong>Malicious javascript:</strong> No.</span><br>
                        <span><strong>Malicious iframes:</strong> No.</span><br>
                        <span><strong>Suspicious redirections (htaccess):</strong> No.</span><br>
                        <span><strong>Blackhat SEO Spam:</strong> No.</span><br>
                        <span><strong>Anomaly detection:</strong> Clean.</span><br>
                    <?php else: ?>
                        <?php
                        foreach( $res['MALWARE']['WARN'] as $malres ){
                            if( !is_array($malres) ){
                                echo htmlspecialchars($malres);
                            }else{
                                $mwdetails = explode("\n", htmlspecialchars($malres[1]));
                                echo htmlspecialchars($malres[0])."\n<br />". substr($mwdetails[0], 1)."<br />\n";
                            }
                        }
                        ?>
                    <?php endif; ?>

                    <p>
                        <i>
                            More details here: <a href="http://sitecheck.sucuri.net/scanner/?scan=<?php echo $website_scanned; ?>">
                            http://sitecheck.sucuri.net/scanner/?scan=<?php echo $website_scanned; ?></a>
                        </i>
                        <hr />
                        <i>
                            If our free scanner did not detect any issue, you may have a more complicated and hidden
                            problem. You can try our <a href="admin.php?page=sucuriscan_core_integrity">WordPress integrity
                            checks</a> or sign up with Sucuri <a target="_blank" href="http://sucuri.net/signup">here</a>
                            for a complete and in depth scan+cleanup (not included in the free checks).
                        </i>
                    </p>

                </div>
            </div>


            <div class="postbox sucuriscan-border <?php _e($sucuriscan_css_blacklist) ?>">
                <h3>
                    <?php if( $blacklist_warns_exists ): ?>
                        Site blacklisted
                    <?php else: ?>
                        Site blacklist-free
                    <?php endif; ?>
                </h3>

                <div class="inside">
                    <?php
                    foreach(array(
                        'INFO'=>'CLEAN',
                        'WARN'=>'WARNING'
                    ) as $type=>$group_title){
                        if( isset($res['BLACKLIST'][$type]) ){
                            foreach($res['BLACKLIST'][$type] as $blres){
                                $report_site = htmlspecialchars($blres[0]);
                                $report_url = htmlspecialchars($blres[1]);
                                echo "<b>{$group_title}: </b>{$report_site} <a href='{$report_url}' target='_blank'>{$report_url}</a><br />";
                            }
                        }
                    }
                    ?>
                </div>
            </div>


            <div class="postbox sucuriscan-border <?php _e($sucuriscan_css_wpupdate) ?>">
                <h3>
                    <?php if( $wordpress_updated ): ?>
                        System info
                    <?php else: ?>
                        System info (need to update)
                    <?php endif; ?>
                </h3>

                <div class="inside">
                    <b>Site:</b> <?php echo $res['SCAN']['SITE'][0]; ?> (<?php echo $res['SCAN']['IP'][0]; ?>)<br />
                    <b>PHP (version installed): </b> <?php echo phpversion(); ?><br />
                    <b>WordPress (installed):</b> <?php echo $wp_version; ?><br />
                    <?php if( !$wordpress_updated ): ?>
                        <b>WordPress (update):</b> <?php echo $updates[0]->version; ?><br />
                        <a href="<?php echo admin_url('update-core.php'); ?>" class="button button-primary">Update</a>
                    <?php endif; ?>
                    <?php
                    if( isset($res['SYSTEM']['NOTICE']) ){
                        foreach( $res['SYSTEM']['NOTICE'] as $notres ){
                            if( is_array($notres) ){
                                echo htmlspecialchars($notres[0]).chr(32).htmlspecialchars($notres[1]);
                            }else{
                                echo htmlspecialchars($notres)."<br />\n";
                            }
                        }
                    }
                    ?>
                </div>
            </div>
        </div>

    <?php endif; ?>


    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_template('base', array(
        'PageContent' => $_html,
        'PageStyleClass' => 'scanner-results',
    ));
    return;
}

/**
 * WordPress core integrity page.
 *
 * It checks whether the WordPress core files are the original ones, and the state
 * of the themes and plugins reporting the availability of updates. It also checks
 * the user accounts under the administrator group.
 *
 * @return void
 */
function sucuriscan_core_integrity_page(){

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Integrity Check') );
    }

    if( isset($_POST['wpsucuri-core-integrity']) ){
        if( !wp_verify_nonce($_POST['sucuriscan_core_integritynonce'], 'sucuriscan_core_integritynonce') ){
            unset($_POST['wpsucuri-core_integrity']);
        }
    }

    ob_start();
    ?>

    <div id="poststuff">
        <?php
        sucuriscan_core_integrity_function_wrapper(
            'sucuriwp_core_integrity_check',
            'Verify Integrity of WordPress Core Files',
            'This test will check wp-includes, wp-admin, and the top directory files against the latest WordPress
            hashing database. If any of those files were modified, it is a big sign of a possible compromise.'
        );

        sucuriscan_core_integrity_wp_content_wrapper();

        sucuriscan_core_integrity_function_wrapper(
            'sucuriwp_list_admins',
            'Admin User Dump',
            'List all administrator users and their latest login time.'
        );

        sucuriscan_core_integrity_function_wrapper(
            'sucuriwp_check_addons',
            'Outdated Addon list',
            'This test will list any outdated plugins and themes (not active addons may not be shown).'
        );
        ?>
    </div>

    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_template('base', array(
        'PageContent' => $_html,
        'PageStyleClass' => 'core-integrity'
    ));
    return;
}

/**
 * Print the HTML code with the form needed to check the integrity of specific
 * parts of the site and administrator panel.
 *
 * @param  string $function_name Name of the function that will be executed on form submission.
 * @param  string $stitle        Title of the HTML panel.
 * @param  string $description   Explanation of the action that will be performed once the form is submitted.
 * @return void
 */
function sucuriscan_core_integrity_function_wrapper($function_name='', $stitle='', $description=''){ ?>
    <div class="postbox">
        <h3><?php _e($stitle); ?></h3>

        <div class="inside">
            <form method="post">
                <input type="hidden" name="<?php _e($function_name) ?>nonce" value="<?php echo wp_create_nonce($function_name.'nonce'); ?>" />
                <input type="hidden" name="<?php _e($function_name) ?>" value="1" />
                <p><?php _e($description) ?></p>
                <input class="button-primary" type="submit" name="<?php _e($function_name) ?>" value="Check" />
            </form>

            <?php
            if( isset($_POST[$function_name.'nonce']) && isset($_POST[$function_name]) ){
                if( function_exists($function_name) ){
                    $function_name();
                }
            }
            ?>
        </div>
    </div>
<?php }

/**
 * List all files inside wp-content that have been modified in the last days.
 *
 * @return void
 */
function sucuriscan_core_integrity_wp_content_wrapper(){ ?>
    <div class="postbox">
        <h3>Latest modified files</h3>
        <div class="inside">
            <form method="post">
                <input type="hidden" name="sucuriwp_content_checknonce" value="<?php echo wp_create_nonce('sucuriwp_content_checknonce'); ?>" />
                <input type="hidden" name="sucuriwp_content_check" value="sucuriwp_content_check" />
                <p>
                    This test will list all files inside wp-content that have been modified in the past
                    <select name="sucuriwp_content_check_back">
                        <?php foreach(array( 1,3,7,30 ) as $days): ?>
                            <?php $selected =
                                ( isset($_POST['sucuriwp_content_check_back']) && $_POST['sucuriwp_content_check_back']==$days )
                                ? 'selected="selected"' : ''; ?>
                            <option value="<?php echo $days; ?>" <?php echo $selected; ?>><?php echo $days; ?></option>
                        <?php endforeach; ?>
                    </select> days. (select the number of days first)
                </p>
                <input class="button-primary" type="submit" name="sucuriwp_content_check" value="Check">
            </form>

            <?php if (
                isset($_POST['sucuriwp_content_checknonce'])
                // && wp_verify_nonce($_POST['sucuriwp_content_checknonce'], 'sucuriwp_content_checknonce')
                && isset($_POST['sucuriwp_content_check'])
            ): ?>
                <table class="wp-list-table widefat sucuriscan-table sucuriscan-table-doubletitle sucuriscan-lastmodified">
                    <thead>
                        <tr>
                            <th colspan="2">wp_content latest modified files</th>
                        </tr>
                        <tr>
                            <th class="manage-column">Filepath</th>
                            <th class="manage-column">Modification date/time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $wp_content_hashes = read_dir_r(ABSPATH.'wp-content', true);
                        $days = htmlspecialchars(trim((int)$_POST['sucuriwp_content_check_back']));
                        $back_days = current_time( 'timestamp' ) - ( $days * 86400);
                        $counter = 0;

                        foreach ( $wp_content_hashes as $key => $value) {
                            if ($value['time'] >= $back_days ){
                                $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                                $date =  date('d-m-Y H:i:s', $value['time']);
                                printf('<tr class="%s"><td>%s</td><td>%s</td></tr>', $css_class, $key, $date);
                                $counter += 1;
                            }
                        }
                        ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
<?php }

/**
 * Retrieve a list of md5sum and last modification time of all the files in the
 * folder specified. This is a recursive function.
 *
 * @param  string  $dir      The base path where the scanning will start.
 * @param  boolean $recursiv Either TRUE or FALSE if the scan should be performed recursively.
 * @return array             List of arrays containing the md5sum and last modification time of the files found.
 */
function read_dir_r($dir = "./", $recursiv = false){
    $skipname  = basename(__FILE__);
    $skipname .= ",_sucuribackup,wp-config.php";

    $files_info = array();

    $dir_handler = opendir($dir);

    while(($entry = readdir($dir_handler)) !== false) {
        if ($entry != "." && $entry != "..") {
            $dir = preg_replace("/^(.*)(\/)+$/", "$1", $dir);
            $item = sprintf( '%s/%s', $dir, $entry );

            if (is_file($item)) {
                $skip_parts = explode(",", $skipname);

                foreach ($skip_parts as $skip) {
                    if (strpos($item,$skip) !== false) {
                       continue 2;
                    }
                }

                $md5 = @md5_file($item);
                $time_stamp = @filectime($item);
                $item_name = str_replace(ABSPATH, "./", $item);
                $files_info[$item_name] = array(
                    'md5'   => $md5,
                    'time' => $time_stamp
                );
            }

            elseif (is_dir($item) && $recursiv) {
                $files_info = array_merge( $files_info , read_dir_r($item) );
            }
        }
    }

    closedir($dir_handler);
    return $files_info;
}

/**
 * Compare the md5sum of the core files in the current site with the hashes hosted
 * remotely in Sucuri servers. These hashes are updated every time a new version
 * of WordPress is released.
 *
 * @return void
 */
function sucuriwp_core_integrity_check(){

    global $wp_version;

    $curlang = get_bloginfo("language");

    $cp = 0;
    $updates = get_core_updates();
    if( !is_array($updates) || empty($updates) || $updates[0]->response=='latest' ){
        $cp = 1;
    }
    if(strcmp($wp_version, "3.7") < 0)
    {
        $cp = 0;
    }
    $wp_version = htmlspecialchars($wp_version);

    if($cp == 0)
    {
        echo '<p><img style="position:relative;top:5px" height="22" width="22" src="'.SUCURI_URL.'/inc/images/warn.png" />'
            .'&nbsp; The current version of your site was detected as <code>'.$wp_version.'</code> which is different to the '
            .'official latest version. The integrity check can not run using this version number <a href="'.admin_url('update-core.php').'">'
            .'update now</a> to be able to run the integrity check.</p>';
    }
    else
    {
        $latest_hashes = sucuriscan_check_wp_integrity($wp_version);
        if($latest_hashes){
            sucuriscan_draw_corefiles_status(array(
                'added'=>$latest_hashes['added'],
                'removed'=>$latest_hashes['removed'],
                'modified'=>$latest_hashes['bad']
            ));
        }else{
            sucuriscan_admin_notice('error', 'Error retrieving the wordpress core hashes, try again.');
        }
    }
}

/**
 * List all the WordPress core files modified until now.
 *
 * @param  array  $list List of WordPress core files modified.
 * @return void
 */
function sucuriscan_draw_corefiles_status($list=array()){
    if( is_array($list) && !empty($list) ): ?>
        <table class="wp-list-table widefat sucuriscan-table sucuriscan-corefiles">
            <tbody>
                <?php
                foreach( $list as $diff_type=>$file_list ){
                    $counter = 0;
                    printf('<tr><th>Core File %s: %d</th></tr>', ucwords($diff_type), sizeof($file_list));
                    foreach($file_list as $filepath){
                        $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                        printf('<tr class="%s"><td>%s</td></tr>', $css_class, $filepath);
                        $counter += 1;
                    }
                }
                ?>
            </tbody>
        </table>
    <?php endif; ?>
<?php }

/**
 * List all the user administrator accounts.
 *
 * @see http://codex.wordpress.org/Class_Reference/WP_User_Query
 *
 * @return void
 */
function sucuriwp_list_admins(){

    global $wpdb;

    // Page pseudo-variables initialization.
    $template_variables = array(
        'AdminUsers.UserList'=>''
    );

    $user_query = new WP_User_Query(array( 'role' => 'Administrator' ));
    $admins = $user_query->get_results();

    foreach( (array)$admins as $admin ){
        $admin->lastlogins = sucuriscan_get_logins(5, $admin->ID);

        $user_snippet = array(
            'AdminUsers.Username'=>$admin->user_login,
            'AdminUsers.Email'=>$admin->user_email,
            'AdminUsers.LastLogins'=>'',
            'AdminUsers.UserURL'=>admin_url('user-edit.php?user_id='.$admin->ID)
        );

        if( !empty($admin->lastlogins) ){
            $user_snippet['AdminUsers.NoLastLogins'] = 'hidden';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'visible';

            foreach($admin->lastlogins as $lastlogin){
                $user_snippet['AdminUsers.LastLogins'] .= sucuriscan_get_snippet('integrity-admins-lastlogin', array(
                    'AdminUsers.RemoteAddr'=>$lastlogin->user_remoteaddr,
                    'AdminUsers.Datetime'=>$lastlogin->user_lastlogin
                ));
            }
        }else{
            $user_snippet['AdminUsers.NoLastLogins'] = 'visible';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'hidden';
        }

        $template_variables['AdminUsers.UserList'] .= sucuriscan_get_snippet('integrity-admins', $user_snippet);
    }

    echo sucuriscan_get_section('integrity-admins', $template_variables);
}

/**
 * Check if any installed plugin and theme has an update available.
 *
 * @return void
 */
function sucuriwp_check_addons(){ ?>

    <table class="wp-list-table widefat sucuriscan-table sucuriscan-table-doubletitle sucuriscan-plugins-update">
        <tbody>
            <tr>
                <th colspan="4">Outdated Plugins</th>
            </tr>

            <?php
            // Check plugins.
            do_action('wp_update_plugins');
            wp_update_plugins();
            $update_plugins = get_site_transient('update_plugins');
            $plugins_need_update = (bool) !empty($update_plugins->response);
            ?>

            <tr>
                <th>Plugin</th>
                <th>Installed Version</th>
                <th>New Version</th>
                <th>&nbsp;</th>
            </tr>

            <?php if( $plugins_need_update ): ?>
                <?php
                $counter = 0;
                foreach( $update_plugins->response as $rel_path => $plugin_info ):
                    $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $rel_path );
                    $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                    $counter += 1;
                    ?>

                    <tr class="<?php _e($css_class) ?>">
                        <td><?php _e($plugin_data['Title']) ?></td>
                        <td><?php _e($plugin_data['Version']) ?></td>
                        <td><?php _e($plugin_info->new_version) ?></td>
                        <td><a href="<?php _e($plugin_info->package) ?>" target="_blank">Download</a></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="4">All plugins are up-to-date.</td>
                </tr>
            <?php endif; ?>

            <?php
            // Check themes.
            do_action('wp_update_themes');
            wp_update_themes();
            $update_themes = get_theme_updates();
            $themes_need_update = (bool) !empty($update_themes);
            ?>

            <tr>
                <th>Theme</th>
                <th>Installed Version</th>
                <th>New Version</th>
                <th>&nbsp;</th>
            </tr>

            <?php if( $themes_need_update ): ?>
                <?php
                $counter = 0;
                foreach( $update_themes as $stylesheet => $theme ):
                    $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                    $counter += 1;
                    ?>

                    <tr class="<?php _e($css_class) ?>">
                        <td><?php _e($theme->display('Name')) ?></td>
                        <td><?php _e($theme->display('Version')) ?></td>
                        <td><?php _e($theme->update['new_version']) ?></td>
                        <td><a href="<?php _e($theme->update['package']) ?>" target="_blank">Download</a></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="4">All themes are up-to-date.</td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>

<?php }

/**
 * Retrieve a list with the checksums of the files in a specific version of WordPress.
 *
 * @param  integer $version Valid version number of the WordPress project.
 * @return object           Associative object with the relative filepath and the checksums of the project files.
 */
function sucuriscan_get_official_checksums($version=0){
    $api_url = sprintf('http://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US', $version);

    $request = wp_remote_get($api_url);
    if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
        $json_data = json_decode($request['body']);
        if( $json_data->checksums !== FALSE ){
            return $json_data->checksums;
        }
    }

    return FALSE;
}

/**
 * Check whether the core WordPress files where modified, removed or if any file
 * was added to the core folders. This function returns an associative array with
 * these keys:
 *
 * <ul>
 *   <li>bad: Files with a different checksum according to the official files of the WordPress version filtered,</li>
 *   <li>good: Files with the same checksums than the official files,</li>
 *   <li>removed: Official files which are not present in the local project,</li>
 *   <li>added: Files present in the local project but not in the official WordPress packages.</li>
 * </ul>
 *
 * @param  integer $version Valid version number of the WordPress project.
 * @return array            Associative array with these keys: bad, good, removed, added.
 */
function sucuriscan_check_wp_integrity($version=0){
    $latest_hashes = sucuriscan_get_official_checksums($version);

    if( !$latest_hashes ){ return FALSE; }

    $output = array( 'bad'=>array(), 'good'=>array(), 'removed'=>array(), 'added'=>array() );

    // Get current filesystem tree.
    $wp_top_hashes = read_dir_r( ABSPATH , false);
    $wp_admin_hashes = read_dir_r( ABSPATH . 'wp-admin', true);
    $wp_includes_hashes = read_dir_r( ABSPATH . 'wp-includes', true);
    $wp_core_hashes = array_merge( $wp_top_hashes, $wp_admin_hashes, $wp_includes_hashes );

    // Compare remote and local md5sums and search removed files.
    foreach( $latest_hashes as $filepath=>$remote_checksum ){
        $full_filepath = sprintf('%s/%s', ABSPATH, $filepath);
        if( file_exists($full_filepath) ){
            $local_checksum = @md5_file($full_filepath);
            if( $local_checksum && $local_checksum == $remote_checksum ){
                $output['good'][] = $filepath;
            }else{
                $output['bad'][] = $filepath;
            }
        }else{
            $output['removed'][] = $filepath;
        }
    }

    // Search added files (files not common in a normal wordpress installation).
    foreach( $wp_core_hashes  as $filepath=>$extra_info ){
        $filepath = preg_replace('/^\.\/(.*)/', '$1', $filepath);
        if( !property_exists($latest_hashes, $filepath) ){
            $output['added'][] = $filepath;
        }
    }

    return $output;
}

/**
 * Sucuri one-click hardening page.
 *
 * It loads all the functions defined in /lib/hardening.php and shows the forms
 * that the administrator can use to harden multiple parts of the site.
 *
 * @return void
 */
function sucuriscan_hardening_page(){

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Hardening') );
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( !wp_verify_nonce($_POST['sucuriscan_hardening_nonce'], 'sucuriscan_hardening_nonce') ){
            unset($_POST['wpsucuri-doharden']);
        }
    }

    ob_start();
    ?>

    <div id="poststuff">
        <form method="post">
            <input type="hidden" name="sucuriscan_hardening_nonce" value="<?php echo wp_create_nonce('sucuriscan_hardening_nonce'); ?>" />
            <input type="hidden" name="wpsucuri-doharden" value="wpsucuri-doharden" />

            <?php
            sucuriscan_harden_version();
            sucuriscan_cloudproxy_enabled();
            sucuri_harden_removegenerator();
            sucuriscan_harden_upload();
            sucuriscan_harden_wpcontent();
            sucuriscan_harden_wpincludes();
            sucuriscan_harden_phpversion();
            ?>
        </form>
    </div>

    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_template('base', array(
        'PageContent' => $_html,
        'PageStyleClass' => 'hardening'
    ));
    return;
}

/**
 * Print the HTML code to show the title of a hardening option box.
 *
 * @param  string $msg The title of the hardening option.
 * @return void
 */
function sucuriscan_wrapper_open($msg){
    ?>
    <div class="postbox">
        <h3><?php echo $msg; ?></h3>
        <div class="inside">
    <?php
}

/**
 * Close the HTML tags of the containers opened with __ss_wraphardeningboxopen()
 *
 * @return void
 */
function sucuriscan_wrapper_close(){
    ?>
    </div>
    </div>
    <?php
}

/**
 * Print an error message in the interface.
 *
 * @param  string $message The text string that will be shown inside the error box.
 * @return void
 */
function sucuriscan_harden_error($message){
    return('<div id="message" class="error"><p>'.$message.'</p></div>');
}

/**
 * Print a success message in the interface.
 *
 * @param  string $message The text string that will be shown inside the success box.
 * @return void
 */
function sucuriscan_harden_ok($message){
    return( '<div id="message" class="updated"><p>'.$message.'</p></div>');
}

/**
 * Generate the HTML code necessary to show a form with the options to harden
 * a specific part of the WordPress installation, if the Status variable is
 * set as a positive integer the button is shown as "unharden".
 *
 * @param  integer $status      Either one or zero representing the state of the hardening, one for secure, zero for insecure.
 * @param  string  $type        Name of the hardening option, this will be used through out the form generation.
 * @param  string  $messageok   Message that will be shown if the hardening was executed.
 * @param  string  $messagewarn Message that will be shown if the hardening is not executed.
 * @param  string  $desc        Optional description of the hardening.
 * @param  string  $updatemsg   Optional explanation of the hardening after the submission of the form.
 * @return void
 */
function sucuriscan_harden_status($status=0, $type='', $messageok='', $messagewarn='', $desc = NULL, $updatemsg = NULL){
    if($desc != NULL)
    {
        echo "<p>$desc</p>";
    }

    $btn_string = '';
    if( $type != NULL ){
        if( $status == 1 ){
            $btn_string = sprintf('<input type="submit" name="%s_unharden" value="Revert hardening" class="button-secondary" />', $type);
        } else {
            $btn_string = sprintf('<input type="submit" name="%s" value="Harden" class="button-primary" />', $type);
        }
    }

    $message = ( $status == 1 ) ? $messageok : $messagewarn;
    printf( '<div class="sucuriscan-hstatus sucuriscan-hstatus-%d">%s<span>%s</span></div>', $status, $btn_string, $message );
    if($updatemsg != NULL){
        printf( '<p>%s</p>', $updatemsg );
    }
}

/**
 * Check whether the version number of the WordPress installed is the latest
 * version available officially.
 *
 * @return void
 */
function sucuriscan_harden_version(){
    global $wp_version;

    $updates = get_core_updates();
    if(
        !is_array($updates)
        || empty($updates)
        || $updates[0]->response == 'latest'
    ){
        $cp = 1;
    } else {
        $cp = 0;
    }

    if(strcmp($wp_version, "3.7") < 0)
    {
        $cp = 0;
    }

    $wp_version = htmlspecialchars($wp_version);
    $initial_msg = 'Why keep your site updated? WordPress is an open-source
        project which means that with every update the details of the changes made
        to the source code are made public, if there were security fixes then
        someone with malicious intent can use this information to attack any site
        that has not been upgraded.';
    $messageok = sprintf('Your WordPress installation (%s) is current.', $wp_version);
    $messagewarn = sprintf(
        'Your current version (%s) is not current.<br>
        <a href="update-core.php" class="button-primary">Update now!</a>',
        $wp_version
    );

    sucuriscan_wrapper_open('Verify WordPress Version');
    sucuriscan_harden_status( $cp, NULL, $messageok, $messagewarn, $initial_msg );
    sucuriscan_wrapper_close();
}

/**
 * Notify the state of the hardening for the removal of the Generator tag in
 * HTML code printed by WordPress to show the current version number of the
 * installation.
 *
 * @return void
 */
function sucuri_harden_removegenerator(){
    /* Enabled by default with this plugin. */
    $cp = 1;

    sucuriscan_wrapper_open("Remove WordPress Version");

    sucuriscan_harden_status($cp, NULL,
                         "WordPress version properly hidden", NULL,
                         "It checks if your WordPress version is being hidden".
                         " from being displayed in the generator tag ".
                         "(enabled by default with this plugin).");

    sucuriscan_wrapper_close();
}

/**
 * Check whether the WordPress upload folder is protected or not.
 *
 * A htaccess file is placed in the upload folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself.
 *
 * @return void
 */
function sucuriscan_harden_upload(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = dirname(sucuriscan_dir_filepath())."/.htaccess";

    if(!is_readable($htaccess_upload))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file($htaccess_upload);
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_upload']) && $cp == 0 )
        {
            if(@file_put_contents($htaccess_upload,
                                 "\n<Files *.php>\ndeny from all\n</Files>")===FALSE)
            {
                $upmsg = sucuriscan_harden_error("ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.");
            }
            else
            {
                $upmsg = sucuriscan_harden_ok("COMPLETE: Upload directory successfully hardened");
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_upload_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;
                if( preg_match('/<Files \*\.php>\ndeny from all\n<\/Files>/', $htaccess_content, $match) ){
                    $htaccess_content = str_replace("<Files *.php>\ndeny from all\n</Files>", '', $htaccess_content);
                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }
                sucuriscan_admin_notice('updated', '<strong>OK.</strong> WP-Content Uploads directory protection reverted.');
            }else{
                $harden_process = '<strong>Error.</strong> The <code>wp-content/uploads/.htaccess</code> does
                    not exists or is not writable, you will need to remove the following code manually there:
                    <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>';
                sucuriscan_admin_notice('error', $harden_process);
            }
        }
    }

    sucuriscan_wrapper_open("Protect Uploads Directory");
    sucuriscan_harden_status($cp, "sucuriscan_harden_upload",
                         "Upload directory properly hardened",
                         "Upload directory not hardened",
                         "It checks if your upload directory allows PHP ".
                         "execution or if it is browsable.", $upmsg);
    sucuriscan_wrapper_close();
}

/**
 * Check whether the WordPress content folder is protected or not.
 *
 * A htaccess file is placed in the content folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself.
 *
 * @return void
 */
function sucuriscan_harden_wpcontent(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = ABSPATH."/wp-content/.htaccess";

    if(!is_readable($htaccess_upload))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file($htaccess_upload);
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_wpcontent']) && $cp == 0 )
        {
            if(@file_put_contents($htaccess_upload,
                                 "\n<Files *.php>\ndeny from all\n</Files>")===FALSE)
            {
                $upmsg = sucuriscan_harden_error("ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.");
            }
            else
            {
                $upmsg = sucuriscan_harden_ok("COMPLETE: wp-content directory successfully hardened");
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_wpcontent_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;
                if( preg_match('/<Files \*\.php>\ndeny from all\n<\/Files>/', $htaccess_content, $match) ){
                    $htaccess_content = str_replace("<Files *.php>\ndeny from all\n</Files>", '', $htaccess_content);
                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }
                sucuriscan_admin_notice('updated', '<strong>OK.</strong> WP-Content directory protection reverted.');
            }else{
                $harden_process = '<strong>Error.</strong> The <code>wp-content/.htaccess</code> does
                    not exists or is not writable, you will need to remove the following code manually there:
                    <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>';
                sucuriscan_admin_notice('error', $harden_process);
            }
        }
    }

    sucuriscan_wrapper_open("Restrict wp-content Access");
    sucuriscan_harden_status(
        $cp,
        'sucuriscan_harden_wpcontent',
        'WP-content directory properly hardened',
        'WP-content directory not hardened',
        'This option blocks direct PHP access to any file inside wp-content. If you experience any
        issue after this with a theme or plugin in your site, like for example images not displaying,
        remove the <code>.htaccess</code> file located at the <code>/wp-content/</code> directory.',
        $upmsg);
    sucuriscan_wrapper_close();
}

/**
 * Check whether the WordPress includes folder is protected or not.
 *
 * A htaccess file is placed in the includes folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself, there are some exceptions for some specific files that must
 * be available publicly.
 *
 * @return void
 */
function sucuriscan_harden_wpincludes(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = ABSPATH."/wp-includes/.htaccess";

    if(!is_readable($htaccess_upload))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file($htaccess_upload);
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_wpincludes']) && $cp == 0 )
        {
            if(@file_put_contents($htaccess_upload,
                                 "\n<Files *.php>\ndeny from all\n</Files>\n<Files wp-tinymce.php>\nallow from all\n</Files>\n")===FALSE)
            {
                $upmsg = sucuriscan_harden_error("ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.");
            }
            else
            {
                $upmsg = sucuriscan_harden_ok("COMPLETE: wp-includes directory successfully hardened.");
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_wpincludes_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;
                if( preg_match_all('/<Files (\*|wp-tinymce|ms-files)\.php>\n(deny|allow) from all\n<\/Files>/', $htaccess_content, $match) ){
                    foreach($match[0] as $restriction){
                        $htaccess_content = str_replace($restriction, '', $htaccess_content);
                    }
                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }
                sucuriscan_admin_notice('updated', '<strong>OK.</strong> WP-Includes directory protection reverted.');
            }else{
                $harden_process = '<strong>Error.</strong> The <code>wp-includes/.htaccess</code> does
                    not exists or is not writable, you will need to remove the following code manually there:
                    <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>';
                sucuriscan_admin_notice('error', $harden_process);
            }
        }
    }

    sucuriscan_wrapper_open("Restrict wp-includes Access");
    sucuriscan_harden_status($cp, "sucuriscan_harden_wpincludes",
                         "wp-includes directory properly hardened",
                         "wp-includes directory not hardened",
                         "This option blocks direct PHP access to any file inside wp-includes. ", $upmsg);
    sucuriscan_wrapper_close();
}

/**
 * Check the version number of the PHP interpreter set to work with the site,
 * is considered that old versions of the PHP interpreter are insecure.
 *
 * @return void
 */
function sucuriscan_harden_phpversion(){
    $phpv = phpversion();

    if(strncmp($phpv, "5.", 2) < 0)
    {
        $cp = 0;
    }
    else
    {
        $cp = 1;
    }

    sucuriscan_wrapper_open("Verify PHP Version");
    sucuriscan_harden_status($cp, NULL,
                         "Using an updated version of PHP (v $phpv)",
                         "The version of PHP you are using ($phpv) is not current, not recommended, and/or not supported",
                         "This checks if you have the latest version of PHP installed.", NULL);
    sucuriscan_wrapper_close();
}

/**
 * Check whether the site is behind a secure proxy server or not.
 *
 * @return void
 */
function sucuriscan_cloudproxy_enabled(){
    $btn_string = '';
    $enabled = sucuriscan_is_behind_cloudproxy();
    if( $enabled!==TRUE ){
        $btn_string = '<a href="http://cloudproxy.sucuri.net/" target="_blank" class="button button-primary">Harden</a>';
    }

    sucuriscan_wrapper_open('Verify if your site is protected by a Web Firewall');
    sucuriscan_harden_status(
        $enabled, NULL,
        'Your website is protected by a Website Firewall (WAF)',
        $btn_string . 'Your website is not protected by a Website Firewall (WAF)',
        'A WAF is a protection layer for your web site, blocking all sort of attacks (brute force attempts, DDoS,
        SQL injections, etc) and helping it remain malware and blacklist free. This test checks if your site is
        using <a href="http://cloudproxy.sucuri.net/" target="_blank">Sucuri\'s CloudProxy WAF</a> to protect your site. ',
        NULL
    );
    sucuriscan_wrapper_close();
}

/**
 * Generate and print the HTML code for the Post-Hack page.
 *
 * @return void
 */
function sucuriscan_posthack_page(){

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Post-Hack') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PosthackNonce' => wp_create_nonce('sucuri_posthack_nonce'),
        'WPConfigUpdate.Display' => 'display:none',
        'WPConfigUpdate.NewConfig' => '',
        'ResetPassword.UserList' => ''
    );

    // Process form submission
    if( isset($_POST['sucuri_posthack_action']) ){
        if( !wp_verify_nonce($_POST['sucuri_posthack_nonce'], 'sucuri_posthack_nonce') ){
            wp_die(__('WordPress Nonce verification failed, try again going back and checking the form.') );
        }

        switch($_POST['sucuri_posthack_action']){
            case 'update_wpconfig':
                $update_wpconfig = ( isset($_POST['sucuri_update_wpconfig']) && $_POST['sucuri_update_wpconfig']==1 ) ? TRUE : FALSE;

                if( $update_wpconfig ){
                    $wpconfig_process = sucuriscan_set_new_config_keys();
                    $template_variables['WPConfigUpdate.Display'] = 'display:block';

                    if($wpconfig_process){
                        if( $wpconfig_process['updated']===TRUE ){
                            sucuriscan_admin_notice('updated', '<strong>OK.</strong> WP-Config keys updated successfully. In the textarea bellow you will see the old-keys and the new-keys updated.');
                            $template_variables['WPConfigUpdate.NewConfig'] .= "// Old Keys\n";
                            $template_variables['WPConfigUpdate.NewConfig'] .= $wpconfig_process['old_keys_string'];
                            $template_variables['WPConfigUpdate.NewConfig'] .= "//\n";
                            $template_variables['WPConfigUpdate.NewConfig'] .= "// New Keys\n";
                            $template_variables['WPConfigUpdate.NewConfig'] .= $wpconfig_process['new_keys_string'];
                        }else{
                            sucuriscan_admin_notice('error', '<strong>Error.</strong> The wp-config.php file is not writable, please copy and paste the code shown bellow in the textarea into that file manually.');
                            $template_variables['WPConfigUpdate.NewConfig'] = $wpconfig_process['new_wpconfig'];
                        }
                    }else{
                        sucuriscan_admin_notice('error', '<strong>Error.</strong> The wp-config.php file was not found in the default location.');
                    }
                }else{
                    sucuriscan_admin_notice('error', '<strong>Error.</strong> You need to confirm that you understand the risk of this operation');
                }
                break;
            case 'reset_password':
                $reset_password = ( isset($_POST['sucuri_reset_password']) && $_POST['sucuri_reset_password']==1 ) ? TRUE : FALSE;

                if( $reset_password ){
                    $user_identifiers = isset($_POST['user_ids']) ? $_POST['user_ids'] : array();
                    $pwd_changed = $pwd_not_changed = array();

                    if( is_array($user_identifiers) && !empty($user_identifiers) ){
                        arsort($user_identifiers);
                        foreach($user_identifiers as $user_id){
                            if( sucuriscan_new_password($user_id) ){
                                $pwd_changed[] = $user_id;
                            }else{
                                $pwd_not_changed[] = $user_id;
                            }
                        }
                        if( !empty($pwd_changed) ){
                            sucuriscan_admin_notice('updated', '<strong>OK.</strong> Password changed successfully for users: '.implode(', ',$pwd_changed));
                        }
                        if( !empty($pwd_not_changed) ){
                            sucuriscan_admin_notice('error', '<strong>Error.</strong> Password change failed for users: '.implode(', ',$pwd_not_changed));
                        }
                    }else{
                        sucuriscan_admin_notice('error', '<strong>Error.</strong> You did not select any user account to be reseted');
                    }
                }else{
                    sucuriscan_admin_notice('error', '<strong>Error.</strong> You need to confirm that you understand the risk of this operation');
                }
                break;
            default:
                wp_die(__('Sucuri WP Plugin, invalid form action, go back and try again.'));
                break;
        }
    }

    // Fill the user list for ResetPassword action.
    $counter = 0;
    $user_list = get_users();
    foreach($user_list as $user){
        $counter += 1;
        $user->user_registered_timestamp = strtotime($user->user_registered);
        $user->user_registered_formatted = date('D, M/Y H:i', $user->user_registered_timestamp);
        $user_snippet = sucuriscan_get_snippet('resetpassword', array(
            'ResetPassword.UserId' => $user->ID,
            'ResetPassword.Username' => $user->user_login,
            'ResetPassword.Displayname' => $user->display_name,
            'ResetPassword.Email' => $user->user_email,
            'ResetPassword.Registered' => $user->user_registered_formatted,
            'ResetPassword.Roles' => implode(', ', $user->roles),
            'ResetPassword.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
        ));
        $template_variables['ResetPassword.UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('posthack', $template_variables);
}

/**
 * Generate and print the HTML code for the Last Logins page.
 *
 * This page will contains information of all the logins of the registered users.
 *
 * @return void
 */
function sucuriscan_lastlogins_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'LastLoginsNonce' => wp_create_nonce('sucuriscan_lastlogins_nonce'),
        'UserList' => '',
        'UserListLimit' => SUCURISCAN_LASTLOGINS_USERSLIMIT,
    );

    if( !sucuriscan_lastlogins_datastore_is_writable() ){
        sucuriscan_admin_notice('error', '<strong>Error.</strong> The last-logins datastore
            file is not writable, gives permissions to write in this location:<br>'.
            '<code>'.sucuriscan_lastlogins_datastore_filepath().'</code>');
    }

    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : SUCURISCAN_LASTLOGINS_USERSLIMIT;
    $template_variables['UserList.ShowAll'] = $limit>0 ? 'visible' : 'hidden';

    $counter = 0;
    $user_list = sucuriscan_get_logins($limit);
    foreach($user_list as $user){
        $counter += 1;
        $user_snippet = sucuriscan_get_snippet('lastlogins', array(
            'UserList.Number' => $counter,
            'UserList.UserId' => intval($user->ID),
            'UserList.Username' => ( !is_null($user->user_login) ? $user->user_login : '<em>Unknown</em>' ),
            'UserList.Displayname' => $user->display_name,
            'UserList.Email' => $user->user_email,
            'UserList.Registered' => $user->user_registered,
            'UserList.RemoteAddr' => $user->user_remoteaddr,
            'UserList.Hostname' => $user->user_hostname,
            'UserList.Datetime' => $user->user_lastlogin,
            'UserList.TimeAgo' => sucuriscan_time_ago($user->user_lastlogin),
            'UserList.UserURL' => admin_url('user-edit.php?user_id='.$user->ID),
            'UserList.CssClass' => ( $counter % 2 == 0 ) ? 'alternate' : ''
        ));
        $template_variables['UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('lastlogins', $template_variables);
}

/**
 * Get the filepath where the information of the last logins of all users is stored.
 *
 * @return string Absolute filepath where the user's last login information is stored.
 */
function sucuriscan_lastlogins_datastore_filepath(){
    $plugin_upload_folder = sucuriscan_dir_filepath();
    $datastore_filepath = rtrim($plugin_upload_folder,'/').'/sucuri-lastlogins.php';
    return $datastore_filepath;
}

/**
 * Check whether the user's last login datastore file exists or not, if not then
 * we try to create the file and check again the success of the operation.
 *
 * @return string Absolute filepath where the user's last login information is stored.
 */
function sucuriscan_lastlogins_datastore_exists(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_filepath();

    if( !file_exists($datastore_filepath) ){
        if( @file_put_contents($datastore_filepath, "<?php exit(0); ?>\n", LOCK_EX) ){
            @chmod($datastore_filepath, 0644);
        }
    }

    return file_exists($datastore_filepath) ? $datastore_filepath : FALSE;
}

/**
 * Check whether the user's last login datastore file is writable or not, if not
 * we try to set the right permissions and check again the success of the operation.
 *
 * @return boolean Whether the user's last login datastore file is writable or not.
 */
function sucuriscan_lastlogins_datastore_is_writable(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_exists();
    if($datastore_filepath){
        if( !is_writable($datastore_filepath) ){
            @chmod($datastore_filepath, 0644);
        }
        return is_writable($datastore_filepath) ? $datastore_filepath : FALSE;
    }
    return FALSE;
}

/**
 * Check whether the user's last login datastore file is readable or not, if not
 * we try to set the right permissions and check again the success of the operation.
 *
 * @return boolean Whether the user's last login datastore file is readable or not.
 */
function sucuriscan_lastlogins_datastore_is_readable(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_exists();
    if( $datastore_filepath && is_readable($datastore_filepath) ){
        return $datastore_filepath;
    }
    return FALSE;
}

if( !function_exists('sucuri_set_lastlogin') ){
    /**
     * Add a new user session to the list of last user logins.
     *
     * @param  string $user_login The name of the user account involved in the operation.
     * @return void
     */
    function sucuriscan_set_lastlogin($user_login=''){
        $datastore_filepath = sucuriscan_lastlogins_datastore_is_writable();

        if($datastore_filepath){
            $current_user = get_user_by('login', $user_login);
            $remote_addr = sucuriscan_get_remoteaddr();

            $login_info = array(
                'user_id' => $current_user->ID,
                'user_login' => $current_user->user_login,
                'user_remoteaddr' => $remote_addr,
                'user_hostname' => @gethostbyaddr($remote_addr),
                'user_lastlogin' => current_time('mysql')
            );

            @file_put_contents($datastore_filepath, serialize($login_info)."\n", FILE_APPEND);
        }
    }
    add_action('wp_login', 'sucuriscan_set_lastlogin', 50);
}

/**
 * Retrieve the list of all the user logins from the datastore file.
 *
 * The results of this operation can be filtered by specific user identifiers,
 * or limiting the quantity of entries.
 *
 * @param  integer $limit   How many entries will be returned from the operation.
 * @param  integer $user_id Optional user identifier to filter the results.
 * @return array            The list of all the user logins through the time until now.
 */
function sucuriscan_get_logins($limit=10, $user_id=0){
    $lastlogins = array();
    $datastore_filepath = sucuriscan_lastlogins_datastore_is_readable();

    if($datastore_filepath){
        $parsed_lines = 0;
        $lastlogins_lines = array_reverse(file($datastore_filepath));
        foreach($lastlogins_lines as $line){
            $line = str_replace("\n", '', $line);
            if( preg_match('/^a:/', $line) ){
                $user_lastlogin = unserialize($line);

                /* Only administrators can see all login stats */
                if( !current_user_can('manage_options') ){
                    $current_user = wp_get_current_user();
                    if( $current_user->user_login!=$user_lastlogin['user_login'] ){ continue; }
                }

                /* If an User_Id was specified when this function was called, filter by that number */
                if( $user_id>0 ){
                    if( $user_lastlogin['user_id']!=$user_id ){ continue; }
                }

                /* Get the WP_User object and add extra information from the last-login data */
                $user_account = get_userdata($user_lastlogin['user_id']);
                foreach($user_lastlogin as $user_extrainfo_key=>$user_extrainfo_value){
                    $user_account->data->{$user_extrainfo_key} = $user_extrainfo_value;
                }
                $lastlogins[] = $user_account;
                $parsed_lines += 1;
            }

            if( preg_match('/^([0-9]+)$/', $limit) && $limit>0 ){
                if( $parsed_lines>=$limit ){ break; }
            }
        }
    }

    return $lastlogins;
}

if( !function_exists('sucuri_login_redirect') ){
    /**
     * Hook for the wp-login action to redirect the user to a specific URL after
     * his successfully login to the administrator interface.
     *
     * @param  string  $redirect_to URL where the browser must be originally redirected to, set by WordPress itself.
     * @param  object  $request     Optional parameter set by WordPress itself through the event triggered.
     * @param  boolean $user        WordPress user object with the information of the account involved in the operation.
     * @return string               URL where the browser must be redirected to.
     */
    function sucuriscan_login_redirect($redirect_to='', $request=NULL, $user=FALSE){
        $login_url = !empty($redirect_to) ? $redirect_to : admin_url();
        if( $user instanceof WP_User && $user->ID ){
            $login_url = add_query_arg( 'sucuriscan_lastlogin_message', 1, $login_url );
        }
        return $login_url;
    }
    add_filter('login_redirect', 'sucuriscan_login_redirect', 10, 3);
}

if( !function_exists('sucuri_get_user_lastlogin') ){
    /**
     * Display the last user login at the top of the admin interface.
     *
     * @return void
     */
    function sucuriscan_get_user_lastlogin(){
        if( isset($_GET['sucuriscan_lastlogin_message']) && current_user_can('manage_options') ){
            $current_user = wp_get_current_user();

            // Select the penultimate entry, not the last one.
            $user_lastlogins = sucuriscan_get_logins(2, $current_user->ID);
            $row = isset($user_lastlogins[1]) ? $user_lastlogins[1] : FALSE;

            if($row){
                $message_tpl  = 'The last time you logged in was: %s, from %s - %s';
                $lastlogin_message = sprintf( $message_tpl, date('Y/M/d'), $row->user_remoteaddr, $row->user_hostname );
                $lastlogin_message .= chr(32).'(<a href="'.site_url('wp-admin/admin.php?page='.SUCURISCAN.'_lastlogins').'">View Last-Logins</a>)';
                sucuriscan_admin_notice('updated', $lastlogin_message);
            }
        }
    }
    add_action('admin_notices', 'sucuriscan_get_user_lastlogin');
}

/**
 * Generate and print the HTML code for the InfoSys page.
 *
 * This page will contains information of the system where the site is hosted,
 * also information about users in session, htaccess rules and configuration
 * options.
 *
 * @return void
 */
function sucuriscan_infosys_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'ServerInfo' => sucuriscan_server_info(),
        'LoggedInUsers' => sucuriscan_infosys_loggedin(),
        'Cronjobs' => sucuriscan_show_cronjobs(),
        'HTAccessIntegrity' => sucuriscan_infosys_htaccess(),
        'WordpressConfig' => sucuriscan_infosys_wpconfig(),
    );

    echo sucuriscan_get_template('infosys', $template_variables);
}

/**
 * Find the main htaccess file for the site and check whether the rules of the
 * main htaccess file of the site are the default rules generated by WordPress.
 *
 * @return string The HTML code displaying the information about the HTAccess rules.
 */
function sucuriscan_infosys_htaccess(){
    $htaccess_path = sucuriscan_get_htaccess_path();

    $template_variables = array(
        'HTAccess.Content' => '',
        'HTAccess.Message' => '',
        'HTAccess.MessageType' => '',
        'HTAccess.MessageVisible' => 'hidden',
        'HTAccess.TextareaVisible' => 'hidden',
    );

    if( $htaccess_path ){
        $htaccess_rules = file_get_contents($htaccess_path);

        $template_variables['HTAccess.MessageType'] = 'updated';
        $template_variables['HTAccess.MessageVisible'] = 'visible';
        $template_variables['HTAccess.TextareaVisible'] = 'visible';
        $template_variables['HTAccess.Content'] = $htaccess_rules;
        $template_variables['HTAccess.Message'] .= 'HTAccess file found in this path <code>'.$htaccess_path.'</code>';

        if( empty($htaccess_rules) ){
            $template_variables['HTAccess.TextareaVisible'] = 'hidden';
            $template_variables['HTAccess.Message'] .= '</p><p>The HTAccess file found is completely empty.';
        }
        if( sucuriscan_htaccess_is_standard($htaccess_rules) ){
            $template_variables['HTAccess.Message'] .= '</p><p>
                The main <code>.htaccess</code> file in your site has the standard rules for a WordPress installation. You can customize it to improve the
                performance and change the behaviour of the redirections for pages and posts in your site. To get more information visit the official documentation at
                <a href="http://codex.wordpress.org/Using_Permalinks#Creating_and_editing_.28.htaccess.29" target="_blank">Codex WordPrexx - Creating and editing (.htaccess)</a>';
        }
    }else{
        $template_variables['HTAccess.Message'] = 'Your website does not contains a <code>.htaccess</code> file or it was not found in the default location.';
        $template_variables['HTAccess.MessageType'] = 'error';
        $template_variables['HTAccess.MessageVisible'] = 'visible';
    }

    return sucuriscan_get_section('infosys-htaccess', $template_variables);
}

/**
 * Check whether the rules in a htaccess file are the default options generated
 * by WordPress or if the file has custom options added by other Plugins.
 *
 * @param  string  $rules Optional parameter containing a text string with the content of the main htaccess file.
 * @return boolean        Either TRUE or FALSE if the rules found in the htaccess file specified are the default ones or not.
 */
function sucuriscan_htaccess_is_standard($rules=FALSE){
    if( $rules===FALSE ){
        $htaccess_path = sucuriscan_get_htaccess_path();
        $rules = $htaccess_path ? file_get_contents($htaccess_path) : '';
    }

    if( !empty($rules) ){
        $standard_lines = array(
            '# BEGIN WordPress',
            '<IfModule mod_rewrite\.c>',
            'RewriteEngine On',
            'RewriteBase \/',
            'RewriteRule .index.\.php. - \[L\]',
            'RewriteCond %\{REQUEST_FILENAME\} \!-f',
            'RewriteCond %\{REQUEST_FILENAME\} \!-d',
            'RewriteRule \. \/index\.php \[L\]',
            '<\/IfModule>',
            '# END WordPress',
        );
        $pattern  = '';
        $standard_lines_total = count($standard_lines);
        foreach($standard_lines as $i=>$line){
            if( $i < ($standard_lines_total-1) ){
                $end_of_line = "\n";
            }else{
                $end_of_line = '';
            }
            $pattern .= sprintf("%s%s", $line, $end_of_line);
        }

        if( preg_match("/{$pattern}/", $rules) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Retrieve all the constants and variables with their respective values defined
 * in the WordPress configuration file, only the database password constant is
 * omitted for security reasons.
 *
 * @return string The HTML code displaying the constants and variables found in the wp-config file.
 */
function sucuriscan_infosys_wpconfig(){
    $template_variables = array(
        'WordpressConfig.Rules' => '',
        'WordpressConfig.Total' => 0,
        'WordpressConfig.Content' => '',
        'WordpressConfig.ThickboxURL' => '#TB_inline?',
    );
    $ignore_wp_rules = array('DB_PASSWORD');
    $template_variables['WordpressConfig.ThickboxURL'] .= http_build_query(array(
        'width' => '800',
        'height' => '550',
        'inlineId' => 'sucuriscan-wpconfig-content',
    ));

    $wp_config_path = sucuriscan_get_wpconfig_path();
    if( $wp_config_path ){
        add_thickbox();
        $wp_config_content = file($wp_config_path);
        $template_variables['WordpressConfig.Content'] = file_get_contents($wp_config_path);

        // Read WordPress main configuration file as text plain.
        $wp_config_rules = array();
        foreach( (array)$wp_config_content as $line ){
            $line = str_replace("\n", '', $line);

            // Ignore useless lines and append to the clean string the important lines.
            if( preg_match('/^define\(/', $line) ){
                $line = str_replace('define(', '', $line);
                $line = preg_replace('/\);.*/', '', $line);
                $line_parts = explode(',', $line, 2);
            }
            else if( preg_match('/^\$[a-zA-Z_]+/', $line) ){
                $line_parts = explode('=', $line, 2);
            }
            else{ continue; }

            // Clean and append the rule to the wp_config_rules variable.
            if( isset($line_parts) && count($line_parts)==2 ){
                $key_name = $key_value = '';
                foreach($line_parts as $i=>$line_part){
                    $line_part = trim($line_part);
                    $line_part = ltrim($line_part, '$');
                    $line_part = rtrim($line_part, ';');

                    // Remove single/double quotes at the beginning and end of the string.
                    $line_part = ltrim($line_part, "'");
                    $line_part = rtrim($line_part, "'");
                    $line_part = ltrim($line_part, '"');
                    $line_part = rtrim($line_part, '"');

                    // Assign the clean strings to specific variables.
                    if( $i==0 ){ $key_name  = $line_part; }
                    if( $i==1 ){ $key_value = $line_part; }
                }

                if( !in_array($key_name, $ignore_wp_rules) ){
                    $wp_config_rules[$key_name] = $key_value;
                }
            }
        }

        // Pass the WordPress configuration rules to the template and show them.
        $counter = 0;
        foreach( $wp_config_rules as $var_name=>$var_value ){
            $counter += 1;
            $template_variables['WordpressConfig.Total'] += 1;
            $template_variables['WordpressConfig.Rules'] .= sucuriscan_get_snippet('infosys-wpconfig', array(
                'WordpressConfig.VariableName' => $var_name,
                'WordpressConfig.VariableValue' => htmlentities($var_value),
                'WordpressConfig.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
            ));
        }
    }

    return sucuriscan_get_section('infosys-wpconfig', $template_variables);
}

/**
 * Print a list of all the registered users that are currently in session.
 *
 * @return string The HTML code displaying a list of all the users logged in at the moment.
 */
function sucuriscan_infosys_loggedin(){
    // Get user logged in list.
    $template_variables = array(
        'LoggedInUsers.List' => '',
        'LoggedInUsers.Total' => 0,
    );

    $logged_in_users = sucuriscan_get_online_users(TRUE);
    if( is_array($logged_in_users) && !empty($logged_in_users) ){
        $template_variables['LoggedInUsers.Total'] = count($logged_in_users);

        $counter = 0;
        foreach( (array)$logged_in_users as $logged_in_user ){
            $counter += 1;
            $logged_in_user['last_activity_datetime'] = date('d/M/Y H:i', $logged_in_user['last_activity']);
            $logged_in_user['user_registered_datetime'] = date('d/M/Y H:i', strtotime($logged_in_user['user_registered']));

            $template_variables['LoggedInUsers.List'] .= sucuriscan_get_snippet('infosys-loggedin', array(
                'LoggedInUsers.Id' => $logged_in_user['user_id'],
                'LoggedInUsers.UserURL' => admin_url('user-edit.php?user_id='.$logged_in_user['user_id']),
                'LoggedInUsers.UserLogin' => $logged_in_user['user_login'],
                'LoggedInUsers.UserEmail' => $logged_in_user['user_email'],
                'LoggedInUsers.LastActivity' => $logged_in_user['last_activity_datetime'],
                'LoggedInUsers.Registered' => $logged_in_user['user_registered_datetime'],
                'LoggedInUsers.RemoveAddr' => $logged_in_user['remote_addr'],
                'LoggedInUsers.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
            ));
        }
    }

    return sucuriscan_get_section('infosys-loggedin', $template_variables);
}

/**
 * Get a list of all the registered users that are currently in session.
 *
 * @param  boolean $add_current_user Whether the current user should be added to the list or not.
 * @return array                     List of registered users currently in session.
 */
function sucuriscan_get_online_users($add_current_user=FALSE){
    $users = array();

    if( sucuriscan_is_multisite() ){
        $users = get_site_transient('online_users');
    }else{
        $users = get_transient('online_users');
    }

    // If not online users but current user is logged in, add it to the list.
    if( empty($users) && $add_current_user ){
        $current_user = wp_get_current_user();
        if( $current_user->ID > 0 ){
            sucuriscan_set_online_user($current_user->user_login, $current_user);
            return sucuriscan_get_online_users();
        }
    }

    return $users;
}

/**
 * Update the list of the registered users currently in session.
 *
 * Useful when you are removing users and need the list of the remaining users.
 *
 * @param  array   $logged_in_users List of registered users currently in session.
 * @return boolean                  Either TRUE or FALSE representing the success or fail of the operation.
 */
function sucuriscan_save_online_users($logged_in_users=array()){
    $expiration = 30 * 60;
    if( sucuriscan_is_multisite() ){
        return set_site_transient('online_users', $logged_in_users, $expiration);
    }else{
        return set_transient('online_users', $logged_in_users, $expiration);
    }
}

if( !function_exists('sucuriscan_unset_online_user_on_logout') ){
    /**
     * Remove a logged in user from the list of registered users in session when
     * the logout page is requested.
     *
     * @return void
     */
    function sucuriscan_unset_online_user_on_logout(){
        $current_user = wp_get_current_user();
        $user_id = $current_user->ID;
        $remote_addr = sucuriscan_get_remoteaddr();

        sucuriscan_unset_online_user($user_id, $remote_addr);
    }

    add_action('wp_logout', 'sucuriscan_unset_online_user_on_logout');
}

/**
 * Remove a logged in user from the list of registered users in session using
 * the user identifier and the ip address of the last computer used to login.
 *
 * @param  integer $user_id     User identifier of the account that will be logged out.
 * @param  integer $remote_addr IP address of the computer where the user logged in.
 * @return boolean              Either TRUE or FALSE representing the success or fail of the operation.
 */
function sucuriscan_unset_online_user($user_id=0, $remote_addr=0){
    $logged_in_users = sucuriscan_get_online_users();

    // Remove the specified user identifier from the list.
    if( is_array($logged_in_users) && !empty($logged_in_users) ){
        foreach($logged_in_users as $i=>$user){
            if(
                $user['user_id']==$user_id
                && strcmp($user['remote_addr'],$remote_addr)==0
            ){
                unset($logged_in_users[$i]);
                break;
            }
        }
    }

    return sucuriscan_save_online_users($logged_in_users);
}

if( !function_exists('sucuriscan_set_online_user') ){
    /**
     * Add an user account to the list of registered users in session.
     *
     * @param  string  $user_login The name of the user account that just logged in the site.
     * @param  boolean $user       The WordPress object containing all the information associated to the user.
     * @return void
     */
    function sucuriscan_set_online_user($user_login='', $user=FALSE){
        if( $user ){
            // Get logged in user information.
            $current_user = ($user instanceof WP_User) ? $user : wp_get_current_user();
            $current_user_id = $current_user->ID;
            $remote_addr = sucuriscan_get_remoteaddr();
            $current_time = current_time('timestamp');
            $logged_in_users = sucuriscan_get_online_users();

            // Build the dataset array that will be stored in the transient variable.
            $current_user_info = array(
                'user_id' => $current_user_id,
                'user_login' => $current_user->user_login,
                'user_email' => $current_user->user_email,
                'user_registered' => $current_user->user_registered,
                'last_activity' => $current_time,
                'remote_addr' => $remote_addr
            );

            if( !is_array($logged_in_users) || empty($logged_in_users) ){
                $logged_in_users = array( $current_user_info );
                sucuriscan_save_online_users($logged_in_users);
            }else{
                $do_nothing = FALSE;
                $update_existing = FALSE;
                $item_index = 0;

                // Check if the user is already in the logged-in-user list and update it if is necessary.
                foreach($logged_in_users as $i=>$user){
                    if(
                        $user['user_id']==$current_user_id
                        && strcmp($user['remote_addr'],$remote_addr)==0
                    ){
                        if( $user['last_activity'] < ($current_time - (15 * 60)) ){
                            $update_existing = TRUE;
                            $item_index = $i;
                            break;
                        }else{
                            $do_nothing = TRUE;
                            break;
                        }
                    }
                }

                if($update_existing){
                    $logged_in_users[$item_index] = $current_user_info;
                    sucuriscan_save_online_users($logged_in_users);
                }else if($do_nothing){
                    // Do nothing.
                }else{
                    $logged_in_users[] = $current_user_info;
                    sucuriscan_save_online_users($logged_in_users);
                }
            }
        }
    }

    add_action('wp_login', 'sucuriscan_set_online_user', 10, 2);
}

/**
 * Retrieve a list with the scheduled tasks configured for the site.
 *
 * @return array A list of pseudo-variables and values that will replace them in the HTML template.
 */
function sucuriscan_show_cronjobs(){
    $template_variables = array(
        'Cronjobs.List' => '',
        'Cronjobs.Total' => 0,
    );

    $cronjobs = _get_cron_array();
    $schedules = wp_get_schedules();
    $date_format = _x('M j, Y - H:i', 'Publish box date format', 'cron-view' );
    $counter = 0;

    foreach( $cronjobs as $timestamp=>$cronhooks ){
        foreach( (array)$cronhooks as $hook=>$events ){
            foreach( (array)$events as $key=>$event ){
                $counter += 1;
                $cronjob_snippet = '';
                $template_variables['Cronjobs.Total'] += 1;
                $template_variables['Cronjobs.List'] .= sucuriscan_get_snippet('infosys-cronjobs', array(
                    'Cronjob.Task' => ucwords(str_replace('_',chr(32),$hook)),
                    'Cronjob.Schedule' => $event['schedule'],
                    'Cronjob.Nexttime' => date_i18n($date_format, $timestamp),
                    'Cronjob.Hook' => $hook,
                    'Cronjob.Arguments' => implode(', ', $event['args']),
                    'Cronjob.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
                ));
            }
        }
    }

    return sucuriscan_get_section('infosys-cronjobs', $template_variables);
}

/**
 * Gather information from the server, database engine and PHP interpreter.
 *
 * @param  array $template_variables The hash for the template system, keys are pseudo-variables.
 * @return array                     A list of pseudo-variables and values that will replace them in the HTML template.
 */
function sucuriscan_server_info(){
    global $wpdb;

    if( current_user_can('manage_options') ){
        $memory_usage = function_exists('memory_get_usage') ? round(memory_get_usage()/1024/1024,2).' MB' : 'N/A';
        $mysql_version = $wpdb->get_var('SELECT VERSION() AS version');
        $mysql_info = $wpdb->get_results('SHOW VARIABLES LIKE "sql_mode"');
        $sql_mode = ( is_array($mysql_info) && !empty($mysql_info[0]->Value) ) ? $mysql_info[0]->Value : 'Not set';
        $plugin_runtime_filepath = sucuriscan_dir_filepath('.runtime');
        $plugin_runtime_datetime = file_exists($plugin_runtime_filepath) ? date('r',filemtime($plugin_runtime_filepath)) : 'N/A';

        $template_variables = array(
            'SettingsDisplay'=>'block',
            'PluginVersion'=>SUCURISCAN_VERSION,
            'PluginForceUpdate'=>admin_url('admin.php?page=sucurisec_settings&sucuri_force_update=1'),
            'PluginMD5'=>md5_file(SUCURISCAN_PLUGIN_FILEPATH),
            'PluginRuntimeDatetime'=>$plugin_runtime_datetime,
            'OperatingSystem'=>sprintf('%s (%d Bit)', PHP_OS, PHP_INT_SIZE*8),
            'Server'=>isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'MemoryUsage'=>$memory_usage,
            'MySQLVersion'=>$mysql_version,
            'SQLMode'=>$sql_mode,
            'PHPVersion'=>PHP_VERSION,
        );

        $field_names = array(
            'safe_mode',
            'allow_url_fopen',
            'memory_limit',
            'upload_max_filesize',
            'post_max_size',
            'max_execution_time',
            'max_input_time',
        );

        foreach( $field_names as $php_flag ){
            $php_flag_name = ucwords(str_replace('_', chr(32), $php_flag) );
            $tpl_varname = str_replace(chr(32), '', $php_flag_name);
            $php_flag_value = ini_get($php_flag);
            $template_variables[$tpl_varname] = $php_flag_value ? $php_flag_value : 'N/A';
        }
    }

    return sucuriscan_get_section('infosys-serverinfo', $template_variables);
}


/**
 * Print the HTML code for the plugin about page with information of the plugin,
 * the scheduled tasks, and some settings from the PHP environment and server.
 *
 * @return void
 */
function sucuriscan_about_page(){

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    echo sucuriscan_get_template('about');
}

