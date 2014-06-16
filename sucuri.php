<?php
/*
Plugin Name: Sucuri Security - SiteCheck Malware Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: The <a href="http://sucuri.net">Sucuri Security</a> - SiteCheck Malware Scanner plugin enables you to <strong>scan your WordPress site using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a></strong> right in your WordPress dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.

You can also scan your site at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Author: Sucuri, INC
Version: 1.6.0
Author URI: http://sucuri.net
*/


/**
 * Main file to control the plugin.
 *
 * @package   Sucuri Plugin - SiteCheck Malware Scanner
 * @author    Yorman Arias <yorman.arias@sucuri.net>
 * @author    Daniel Cid   <dcid@sucuri.net>
 * @copyright Since 2010-2014 Sucuri Inc.
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
define('SUCURISCAN_VERSION','1.6.0');

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
 * Remote URL where the public Sucuri API service is running.
 */
// define('SUCURISCAN_API', 'https://wordpress.sucuri.net/');
define('SUCURISCAN_API', 'https://wordpress.sucuri.net/api/');

/**
 * Latest version of the public Sucuri API.
 */
define('SUCURISCAN_API_VERSION', 'v1');

/**
 * The maximum quantity of entries that will be displayed in the last login page.
 */
define('SUCURISCAN_LASTLOGINS_USERSLIMIT', 50);

/**
 * The maximum quantity of entries that will be displayed in the audit logs page.
 */
define('SUCURISCAN_AUDITLOGS_PER_PAGE', 50);

/**
 * The minimum quantity of seconds to wait before each filesystem scan.
 */
define('SUCURISCAN_MINIMUM_RUNTIME', 10800);

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

if( !function_exists('sucuriscan_admin_script_style_registration') ){
    /**
     * Define which javascript and css files will be loaded in the header of the page.
     * @return void
     */
    function sucuriscan_admin_script_style_registration(){
        wp_register_style( 'sucuriscan', SUCURI_URL . '/inc/css/sucuriscan-default-css.css' );
        wp_register_script( 'sucuriscan', SUCURI_URL . '/inc/js/sucuriscan-scripts.js' );

        wp_enqueue_style( 'sucuriscan' );
        wp_enqueue_script( 'sucuriscan' );
    }

    add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );
}

/**
 * Returns the system filepath to the relevant user uploads directory for this
 * site. This is a multisite capable function.
 *
 * @param  string $path The relative path that needs to be completed to get the absolute path.
 * @return string       The full filesystem path including the directory specified.
 */
function sucuriscan_dir_filepath($path = ''){
    $wp_dir_array = wp_upload_dir();
    $wp_dir_array['basedir'] = untrailingslashit($wp_dir_array['basedir']);
    $wp_filepath = $wp_dir_array['basedir'] . '/sucuri/' . $path;

    return $wp_filepath;
}

/**
 * Generate the menu and submenus for the plugin in the admin interface.
 *
 * @return void
 */
function sucuriscan_menu(){
    // Add main menu link.
    add_menu_page(
        'Sucuri Free',
        'Sucuri Free',
        'manage_options',
        'sucuriscan',
        'sucuriscan_page',
        SUCURI_URL . '/inc/images/menu-icon.png'
    );

    $sub_pages = array(
        'sucuriscan' => 'Sucuri Scanner',
        'sucuriscan_auditlogs' => 'Audit Logs',
        'sucuriscan_hardening' => '1-Click Hardening',
        'sucuriscan_core_integrity' => 'WordPress Integrity',
        'sucuriscan_posthack' => 'Post-Hack',
        'sucuriscan_lastlogins' => 'Last Logins',
        'sucuriscan_infosys' => 'Site Info',
        'sucuriscan_settings' => 'Settings',
        'sucuriscan_about' => 'About',
    );

    foreach( $sub_pages as $sub_page_func => $sub_page_title ){
        $page_func = $sub_page_func . '_page';

        add_submenu_page(
            'sucuriscan',
            $sub_page_title,
            $sub_page_title,
            'manage_options',
            $sub_page_func,
            $page_func
        );
    }
}

add_action('admin_menu', 'sucuriscan_menu');
add_action('sucuriscan_scheduled_scan', 'sucuriscan_filesystem_scan');
remove_action('wp_head', 'wp_generator');

/**
 * Validate email address.
 *
 * This use the native PHP function filter_var which is available in PHP >=
 * 5.2.0 if it is not found in the interpreter this function will sue regular
 * expressions to check whether the email address passed is valid or not.
 *
 * @see http://www.php.net/manual/en/function.filter-var.php
 *
 * @param  string $email The string that will be validated as an email address.
 * @return boolean       TRUE if the email address passed to the function is valid, FALSE if not.
 */
function is_valid_email( $email='' ){
    if( function_exists('filter_var') ){
        return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    } else {
        $pattern = '/^([a-z0-9\+_\-]+)(\.[a-z0-9\+_\-]+)*@([a-z0-9\-]+\.)+[a-z]{2,6}$/ix';
        return (bool) preg_match($pattern, $email);
    }
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
function sucuriscan_send_mail( $to='', $subject='', $message='', $data_set=array(), $debug=FALSE ){
    $headers = array();
    $subject = ucwords(strtolower($subject));
    $wp_domain = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : get_option('siteurl');

    if( get_option('sucuriscan_prettify_mails') == 'enabled' ){
        $headers = array( 'Content-type: text/html' );
        $data_set['PrettifyType'] = 'pretty';
    }

    $message = sucuriscan_prettify_mail($subject, $message, $data_set);

    if( $debug ){
        die($message);
    } else {
        wp_mail($to, "Sucuri WP Notification: {$wp_domain} - {$subject}" , $message, $headers);
    }
}

/**
 * Generate a HTML version of the message that will be sent through an email.
 *
 * @param  string $subject  The reason of the message that will be sent.
 * @param  string $message  Body of the message that will be sent.
 * @param  array  $data_set Optional parameter to add more information to the notification.
 * @return string           The message formatted in a HTML template.
 */
function sucuriscan_prettify_mail( $subject='', $message='', $data_set=array() ){
    $prettify_type = isset($data_set['PrettifyType']) ? $data_set['PrettifyType'] : 'simple';
    $template_name = 'notification-' . $prettify_type;
    $remote_addr = sucuriscan_get_remoteaddr();
    $current_user = wp_get_current_user();
    $display_name = 'Unknown user';

    if( $current_user instanceof WP_User ){
        $display_name = sprintf( '%s (%s)', $current_user->display_name, $current_user->user_login );
    }

    $mail_variables = array(
        'TemplateTitle' => 'Sucuri WP Notification',
        'Subject' => $subject,
        'Website' => get_option('siteurl'),
        'RemoteAddress' => $remote_addr,
        'Message' => $message,
        'User' => $display_name,
        'Time' => current_time('mysql'),
    );

    foreach($data_set as $var_key=>$var_value){
        $mail_variables[$var_key] = $var_value;
    }

    return sucuriscan_get_section( $template_name, $mail_variables );
}

/**
 * Prints a HTML alert in the WordPress admin interface.
 *
 * @param  string $type    The type of alert, it can be either Updated or Error.
 * @param  string $message The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_admin_notice($type='updated', $message=''){
    $alert_id = rand(100, 999);
    if( !empty($message) ): ?>
        <div id="sucuri-alert-<?php echo $alert_id; ?>" class="<?php echo $type; ?> sucuri-alert sucuri-alert-<?php echo $type; ?>">
            <a href="javascript:void(0)" class="close" onclick="sucuriscan_alert_close('<?php echo $alert_id; ?>')">&times;</a>
            <p><?php _e($message); ?></p>
        </div>
    <?php endif;
}

/**
 * Prints a HTML alert of type ERROR in the WordPress admin interface.
 *
 * @param  string $error_msg The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_error( $error_msg='' ){
    sucuriscan_admin_notice( 'error', '<b>Sucuri:</b> ' . $error_msg );
}

/**
 * Prints a HTML alert of type INFO in the WordPress admin interface.
 *
 * @param  string $info_msg The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_info( $info_msg='' ){
    sucuriscan_admin_notice( 'updated', '<b>Sucuri:</b> ' . $info_msg );
}

/**
 * Verify the nonce of the previous page after a form submission. If the
 * validation fails the execution of the script will be stopped and a dead page
 * will be printed to the client using the official WordPress method.
 *
 * @return boolean Either TRUE or FALSE if the nonce is valid or not respectively.
 */
function sucuriscan_check_page_nonce(){
    if( !empty($_POST) ){
        $nonce_name = 'sucuriscan_page_nonce';

        if( !isset($_POST[$nonce_name]) || !wp_verify_nonce($_POST[$nonce_name], $nonce_name) ){
            wp_die(__('WordPress Nonce verification failed, try again going back and checking the form.') );

            return FALSE;
        }
    }

    return TRUE;
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
    $page_nonce = wp_create_nonce('sucuriscan_page_nonce');

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);

        $current_page = isset($_GET['page']) ? htmlentities($_GET['page']) : '';
        $params['CurrentURL'] = sprintf( '%s/wp-admin/admin.php?page=%s', site_url(), $current_page );
        $params['SucuriURL'] = SUCURI_URL;
        $params['PageNonce'] = $page_nonce;

        foreach($params as $tpl_key=>$tpl_value){
            $template_content = str_replace("%%SUCURI.{$tpl_key}%%", $tpl_value, $template_content);
        }
    }

    if( $template == 'base' || $type != 'page' ){
        return $template_content;
    } else {
        $get_api_css = sucuriscan_get_api_key() ? 'hidden' : 'visible';

        $base_params = array(
            'PageTitle' => '',
            'PageNonce' => $page_nonce,
            'PageContent' => $template_content,
            'PageStyleClass' => $template,
            'URL.Home' => sucuriscan_get_url(),
            'URL.AuditLogs' => sucuriscan_get_url('auditlogs'),
            'URL.Hardening' => sucuriscan_get_url('hardening'),
            'URL.CoreIntegrity' => sucuriscan_get_url('core_integrity'),
            'URL.PostHack' => sucuriscan_get_url('posthack'),
            'URL.LastLogins' => sucuriscan_get_url('lastlogins'),
            'URL.Settings' => sucuriscan_get_url('settings'),
            'GetApiFormVisibility' => $get_api_css,
        );

        if( isset($params['PageTitle']) ){
            $base_params['PageTitle'] = '('.$params['PageTitle'].')';
        }

        return sucuriscan_get_template('base', $base_params);
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
    $url_path = admin_url('admin.php?page=sucuriscan');

    if( !empty($page) ){
        $url_path .= '_' . $page;
    }

    return $url_path;
}

/**
 * Retrieve a new set of keys for the WordPress configuration file using the
 * official API provided by WordPress itself.
 *
 * @return array A list of the new set of keys generated by WordPress API.
 */
function sucuriscan_get_new_config_keys(){
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
function sucuriscan_set_new_config_keys(){
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
            'updated' => is_writable($wp_config_path),
            'old_keys' => $old_keys,
            'old_keys_string' => $old_keys_string,
            'new_keys' => $new_keys,
            'new_keys_string' => $new_keys_string,
            'new_wpconfig' => $new_wpconfig,
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
function sucuriscan_new_password($user_id=0){
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
function sucuriscan_get_remoteaddr(){
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
 * Find and retrieve the current version of Wordpress installed.
 *
 * @return string The version number of Wordpress installed.
 */
function sucuriscan_get_wpversion(){
    $version = get_option('version');
    if( $version ){ return $version; }

    $wp_version_path = ABSPATH . WPINC . '/version.php';
    if( file_exists($wp_version_path) ){
        include($wp_version_path);
        if( isset($wp_version) ){ return $wp_version; }
    }

    return md5_file(ABSPATH . WPINC . '/class-wp.php');
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
 * Get the email address set by the administrator to receive the notifications
 * sent by the plugin, if the email is missing the WordPress email address is
 * chosen by default.
 *
 * @return string The administrator email address.
 */
function sucuriscan_get_site_email(){
    $email = get_option('admin_email');

    if( is_valid_email($email) ){
        return $email;
    }

    return FALSE;
}

/**
 * Get the clean version of the current domain.
 *
 * @return string The domain of the current site.
 */
function sucuriscan_get_domain(){
    $http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $domain_name =  preg_replace( '/^www\./', '', $http_host );

    return $domain_name;
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
 * Retrieve specific options from the database.
 *
 * Considering the case in which this plugin is installed in a multisite instance
 * of Wordpress, the allowed values for the first parameter of this function will
 * be treated like this:
 *
 * <ul>
 *   <li>all_sucuriscan_options: Will retrieve all the option values created by this plugin in the main site (aka. network),</li>
 *   <li>site_options: Will retrieve all the option values stored in the current site visited by the user (aka. sub-site) excluding the transient options,</li>
 *   <li>sucuriscan_option: Will retrieve one specific option from the network site only if the option starts with the prefix <i>sucuri_<i>.</li>
 * </ul>
 *
 * @param  string $filter_by   Criteria to filter the results, valid values: all_sucuriscan_options, site_options, sucuri_option.
 * @param  string $option_name Optional parameter with the name of the option that will be filtered.
 * @return array               List of options retrieved from the query in the database.
 */
function sucuriscan_get_options_from_db( $filter_by='', $option_name='' ){
    global $wpdb;

    $output = FALSE;
    switch($filter_by){
        case 'all_sucuriscan_options':
            $output = $wpdb->get_results("SELECT * FROM {$wpdb->base_prefix}options WHERE option_name LIKE 'sucuriscan%' ORDER BY option_id ASC");
            break;
        case 'site_options':
            $output = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name NOT LIKE '%_transient_%' ORDER BY option_id ASC");
            break;
        case 'sucuriscan_option':
            $row = $wpdb->get_row( $wpdb->prepare("SELECT option_value FROM {$wpdb->base_prefix}options WHERE option_name = %s LIMIT 1", $option_name) );
            if( $row ){ $output = $row->option_value; }
            break;
    }

    return $output;
}

/**
 * Alias function for the method Common::SucuriScan_Get_Options()
 *
 * This function search the specified option in the database, not only the options
 * set by the plugin but all the options set for the site. If the value retrieved
 * is FALSE the method tries to search for a default value.
 *
 * @param  string $option_name Optional parameter that you can use to filter the results to one option.
 * @return string              The value (or default value) of the option specified.
 */
function sucuriscan_get_option( $option_name='' ){
    return sucuriscan_get_options($option_name);
}

/**
 * Retrieve all the options created by this Plugin from the Wordpress database.
 *
 * The function acts as an alias of WP::get_option() and if the returned value
 * is FALSE it tries to search for a default value to complement the information.
 *
 * @param  string $option_name Optional parameter that you can use to filter the results to one option.
 * @return array               Either FALSE or an Array containing all the sucuri options in the database.
 */
function sucuriscan_get_options( $option_name='' ){
    if( !empty($option_name) ){
        return sucuriscan_get_single_option($option_name);
    }

    $settings = array();
    $results = sucuriscan_get_options_from_db('all_sucuriscan_options');
    foreach( $results as $row ){
        $settings[$row->option_name] = $row->option_value;
    }

    return sucuriscan_get_default_options($settings);
}

/**
 * Retrieve a single option from the database.
 *
 * @param  string $option_name Name of the option that will be retrieved.
 * @return string              Value of the option stored in the database, FALSE if not found.
 */
function sucuriscan_get_single_option( $option_name='' ){
    $is_sucuri_option = preg_match('/^sucuriscan_/', $option_name) ? TRUE : FALSE;

    if( sucuriscan_is_multisite() && $is_sucuri_option ){
        $option_value = sucuriscan_get_options_from_db('sucuriscan_option', $option_name);
    }else{
        $option_value = get_option($option_name);
    }

    if( $option_value === FALSE && $is_sucuri_option ){
        $option_value = sucuriscan_get_default_options($option_name);
    }

    return $option_value;
}

/**
 * Retrieve the default values for some specific options.
 *
 * @param  string|array $settings Either an array that will be complemented or a string with the name of the option.
 * @return string|array           The default values for the specified options.
 */
function sucuriscan_get_default_options( $settings='' ){
    $default_options = array(
        'sucuriscan_api_key' => FALSE,
        'sucuriscan_account' => get_option('admin_email'),
        'sucuriscan_scan_frequency' => 'hourly',
        'sucuriscan_scan_interface' => 'spl',
        'sucuriscan_runtime' => 0,
        'sucuriscan_lastlogin_redirection' => 'enabled',
    );

    if( is_array($settings) ){
        foreach( $default_options as $option_name => $option_value ){
            if( !isset($settings[$option_name]) ){
                $settings[$option_name] = $option_value;
            }
        }
        return $settings;
    }

    if( is_string($settings) ){
        if( isset($default_options[$settings]) ){
            return $default_options[$settings];
        }
    }

    return FALSE;
}

/**
 * Retrieve all the options stored by Wordpress in the database. The options
 * containing the word "transient" are excluded from the results, this function
 * is compatible with multisite instances.
 *
 * @return array All the options stored by Wordpress in the database, except the transient options.
 */
function sucuriscan_get_wp_options(){
    $settings = array();

    $results = sucuriscan_get_options_from_db('site_options');
    foreach( $results as $row ){
        $settings[$row->option_name] = $row->option_value;
    }

    return $settings;
}

/**
 * Check what Wordpress options were changed comparing the values in the database
 * with the values sent through a simple request using a GET or POST method.
 *
 * @param  array  $request The content of the global variable GET or POST considering SERVER[REQUEST_METHOD].
 * @return array           A list of all the options that were changes through this request.
 */
function sucuriscan_what_options_were_changed( $request=array() ){
    $options_changed = array(
        'original' => array(),
        'changed' => array()
    );
    $wp_options = sucuriscan_get_wp_options();

    foreach( $request as $req_name => $req_value ){
        if(
            array_key_exists($req_name, $wp_options)
            && $wp_options[$req_name] != $req_value
        ){
            $options_changed['original'][$req_name] = $wp_options[$req_name];
            $options_changed['changed'][$req_name] = $req_value;
        }
    }
    return $options_changed;
}

/**
 * Class to process files and folders.
 *
 * Here are implemented the functions needed to open, scan, read, create files
 * and folders using the built-in PHP class SplFileInfo. The SplFileInfo class
 * offers a high-level object oriented interface to information for an individual
 * file.
 */
class SucuriScanFileInfo{
    /**
     * Class constructor.
     */
    public function __construct(){
    }

    /**
     * Retrieve a long text string with signatures of all the files contained
     * in the main and subdirectories of the folder specified, also the filesize
     * and md5sum of that file. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @param  string $scan_with Set the tool used to scan the filesystem, SplFileInfo by default.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    public function get_directory_tree_md5($directory='', $scan_with='spl'){
        $project_signatures = '';
        $abs_path = rtrim( ABSPATH, '/' );
        $files = $this->get_directory_tree($directory, $scan_with);
        sort($files);

        foreach( $files as $filepath){
            $filepath = str_replace( $abs_path, $abs_path . '/', $filepath );
            $project_signatures .= sprintf(
                "%s%s%s%s\n",
                md5_file($filepath),
                filesize($filepath),
                chr(32),
                $filepath
            );
        }

        return $project_signatures;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @param  string $scan_with Set the tool used to scan the filesystem, SplFileInfo by default.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    public function get_directory_tree($directory='', $scan_with='spl'){
        $tree = array();

        switch( $scan_with ){
            case 'spl':
                if( $this->is_spl_available() ){
                    $tree = $this->get_directory_tree_with_spl($directory);
                }else{
                    $tree = $this->get_directory_tree($directory, 'opendir');
                }
                break;

            case 'glob':
                $tree = $this->get_directory_tree_with_glob($directory);
                break;

            case 'opendir':
                $tree = $this->get_directory_tree_with_opendir($directory);
                break;

            default:
                $tree = $this->get_directory_tree($directory, 'spl');
                break;
        }

        return $tree;
    }

    /**
     * Check whether the built-in class SplFileObject is available in the system
     * or not, it is required to have PHP >= 5.1.0. The SplFileObject class offers
     * an object oriented interface for a file.
     *
     * @link http://www.php.net/manual/en/class.splfileobject.php
     *
     * @return boolean Whether the PHP class "SplFileObject" is available or not.
     */
    private function is_spl_available(){
        return (bool) class_exists('SplFileObject');
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @link http://www.php.net/manual/en/class.recursivedirectoryiterator.php
     * @see  RecursiveDirectoryIterator extends FilesystemIterator
     * @see  FilesystemIterator         extends DirectoryIterator
     * @see  DirectoryIterator          extends SplFileInfo
     * @see  SplFileInfo
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_spl($directory=''){
        $files = array();
        $filepath = realpath($directory);

        if( !class_exists('FilesystemIterator') ){
            return $this->get_directory_tree($directory, 'opendir');
        }

        $flags = FilesystemIterator::KEY_AS_PATHNAME
            | FilesystemIterator::CURRENT_AS_FILEINFO
            | FilesystemIterator::SKIP_DOTS
            | FilesystemIterator::UNIX_PATHS;
        $objects = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($filepath, $flags),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach( $objects as $filepath=>$fileinfo ){
            $directory = dirname($filepath);
            $filename = $fileinfo->getFilename();

            if( $this->ignore_folderpath($directory, $filename) ){ continue; }
            if( $this->ignore_filepath($directory, $filename) ){ continue; }

            $files[] = $filepath;
        }

        return $files;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_glob($directory=''){
        $files = array();

        $directory_pattern = sprintf( '%s/*', rtrim($directory,'/') );
        $files_found = glob($directory_pattern);

        if( is_array($files_found) ){
            foreach( $files_found as $filepath ){
                $filepath = realpath($filepath);
                $directory = dirname($filepath);
                $filename = array_pop(explode('/', $filepath));

                if( is_dir($filepath) ){
                    if( $this->ignore_folderpath($directory, $filename) ){ continue; }
                    $sub_files = $this->get_directory_tree_with_opendir($filepath);
                    $files = array_merge($files, $sub_files);
                }else{
                    if( $this->ignore_filepath($directory, $filename) ){ continue; }
                    $files[] = $filepath;
                }
            }
        }

        return $files;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_opendir($directory=''){
        $dh = @opendir($directory);
        if( !$dh ){ return FALSE; }

        $files = array();
        while( ($filename = readdir($dh)) !== FALSE ){
            $filepath = realpath($directory.'/'.$filename);

            if( is_dir($filepath) ){
                if( $this->ignore_folderpath($directory, $filename) ){ continue; }
                $sub_files = $this->get_directory_tree_with_opendir($filepath);
                $files = array_merge($files, $sub_files);
            }else{
                if( $this->ignore_filepath($directory, $filename) ){ continue; }
                $files[] = $filepath;
            }
        }

        closedir($dh);
        return $files;
    }

    /**
     * Skip some specific directories and filepaths from the filesystem scan.
     *
     * @param  string  $directory Directory where the scanner is located at the moment.
     * @param  string  $filename  Name of the folder or file being scanned at the moment.
     * @return boolean            Either TRUE or FALSE representing that the scan should ignore this folder or not.
     */
    private function ignore_folderpath($directory='', $filename=''){
        $filepath = realpath($directory.'/'.$filename);

        // Ignoring current and parent folders.
        if( $filename == '.' || $filename == '..' ){ return TRUE; }

        if( $filename == 'sucuri' || strpos($filepath, '/sucuri/') !== FALSE ){ return TRUE; }

        if( is_dir($filepath) ){
            if( ($filename == 'cache') && (strpos($directory, 'wp-content') !== FALSE) ){ return TRUE; }

            if( ($filename == 'w3tc') && (strpos($filepath, 'wp-content/w3tc') !== FALSE) ){ return TRUE; }
        }

        return FALSE;
    }

    /**
     * Skip some specific files from the filesystem scan.
     *
     * @param  string  $directory Directory where the scanner is located at the moment.
     * @param  string  $filename  Name of the folder or file being scanned at the moment.
     * @return boolean            Either TRUE or FALSE representing that the scan should ignore this filename or not.
     */
    private function ignore_filepath($directory='', $filename=''){
        // Ignoring backup files from our clean ups.
        if( strpos($filename, '_sucuribackup.') !== FALSE ){ return TRUE; }

        // Any file maching one of these rules WILL NOT be ignored.
        if(
            ( strpos($filename, '.php')      !== FALSE) ||
            ( strpos($filename, '.htm')      !== FALSE) ||
            ( strpos($filename, '.js')       !== FALSE) ||
            ( strcmp($filename, '.htaccess') == 0     ) ||
            ( strcmp($filename, 'php.ini')   == 0     )
        ){ return FALSE; }

        return TRUE;
    }
}

/**
 * Print a HTML code with a form from where the administrator can check the state
 * of this site through Sucuri SiteCheck.
 *
 * @return void
 */
function sucuriscan_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Malware Scanner') );
    }

    // Execute the SiteCheck scanning on this site.
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

        <div class="sucuriscan-tabs">
            <ul>
                <li>
                    <a href="#" data-tabname="sitecheck-results">SiteCheck Results</a>
                </li>
                <li>
                    <a href="#" data-tabname="website-details">Website Details</a>
                </li>
                <li>
                    <a href="#" data-tabname="blacklist-status">Blacklist Status</a>
                </li>
            </ul>

            <div class="sucuriscan-tab-containers">

                <div id="sucuriscan-sitecheck-results">
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
                                        More details here: <a href="http://sitecheck.sucuri.net/results/<?php _e($website_scanned); ?>"
                                        target="_blank">http://sitecheck.sucuri.net/results/<?php _e($website_scanned); ?></a>
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
                    </div>
                </div>

                <div id="sucuriscan-website-details">
                    <table class="wp-list-table widefat sucuriscan-table">
                        <thead>
                            <tr>
                                <th colspan="2" class="thead-with-button">
                                    <span>System Information</span>
                                    <?php if( !$wordpress_updated ): ?>
                                        <a href="<?php echo admin_url('update-core.php'); ?>" class="button button-primary thead-topright-action">
                                            Update to <?php _e($updates[0]->version) ?>
                                        </a>
                                    <?php endif; ?>
                                </th>
                            </tr>
                        </thead>

                        <tbody>
                            <!-- List of generic information from the site. -->
                            <?php
                            $possible_keys = array(
                                'DOMAIN' => 'Domain Scanned',
                                'IP' => 'Site IP Address',
                                'HOSTING' => 'Hosting Company',
                                'CMS' => 'CMS Found',
                            );
                            $possible_url_keys = array(
                                'JSLOCAL' => 'List of scripts included',
                                'JSEXTERNAL' => 'List of external scripts included',
                                'URL' => 'List of links found',
                            );
                            ?>

                            <?php foreach( $possible_keys as $result_key=>$result_title ): ?>
                                <?php if( isset($res['SCAN'][$result_key]) ): ?>
                                    <?php $result_value = implode(', ', $res['SCAN'][$result_key]); ?>
                                    <tr>
                                        <td><?php _e($result_title) ?></td>
                                        <td><span class="sucuriscan-monospace"><?php _e($result_value) ?></span></td>
                                    </tr>
                                <?php endif; ?>
                            <?php endforeach; ?>

                            <tr>
                                <td>WordPress Version</td>
                                <td><span class="sucuriscan-monospace"><?php _e($wp_version) ?></span></td>
                            </tr>
                            <tr>
                                <td>PHP Version</td>
                                <td><span class="sucuriscan-monospace"><?php _e(phpversion()) ?></span></td>
                            </tr>

                            <!-- List of application details from the site. -->
                            <tr>
                                <th colspan="2">Web application details</th>
                            </tr>
                            <?php foreach( $res['WEBAPP'] as $webapp_key=>$webapp_details ): ?>
                                <?php if( is_array($webapp_details) ): ?>
                                    <?php foreach( $webapp_details as $i=>$details ): ?>
                                        <?php if( is_array($details) ){ $details = isset($details[0]) ? $details[0] : ''; } ?>
                                        <tr>
                                            <td colspan="2">
                                                <span class="sucuriscan-monospace"><?php _e($details) ?></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            <?php endforeach; ?>

                            <?php foreach( $res['SYSTEM']['NOTICE'] as $j=>$notice ): ?>
                                <?php if( is_array($notice) ){ $notice = implode(', ', $notice); } ?>
                                <tr>
                                    <td colspan="2">
                                        <span class="sucuriscan-monospace"><?php _e($notice) ?></span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>

                            <?php foreach( $possible_url_keys as $result_url_key=>$result_url_title ): ?>

                                <?php if( isset($res['LINKS'][$result_url_key]) ): ?>
                                    <tr>
                                        <th colspan="2">
                                            <?php printf(
                                                '%s (%d found)',
                                                __($result_url_title),
                                                count($res['LINKS'][$result_url_key])
                                            ) ?>
                                        </th>
                                    </tr>

                                    <?php foreach( $res['LINKS'][$result_url_key] as $url_path ): ?>
                                        <tr>
                                            <td colspan="2">
                                                <span class="sucuriscan-monospace"><?php _e($url_path) ?></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>

                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div id="sucuriscan-blacklist-status">
                    <div id="poststuff">
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
                    </div>
                </div>
            </div>
        </div>

        <?php if( $malware_warns_exists || $blacklist_warns_exists ): ?>
            <a href="http://sucuri.net/signup/" target="_blank" class="button button-primary button-hero sucuriscan-cleanup-btn">
                Get your site protected with Sucuri
            </a>
        <?php endif; ?>

    <?php endif; ?>


    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_template('base', array(
        'PageTitle' => '(Results)',
        'PageContent' => $_html,
        'PageStyleClass' => 'scanner-results',
    ));
    return;
}

/**
 * Retrieves a URL using a changeable HTTP method, returning results in an
 * array. Results include HTTP headers and content.
 *
 * @see http://codex.wordpress.org/Function_Reference/wp_remote_post
 * @see http://codex.wordpress.org/Function_Reference/wp_remote_get
 *
 * @param  string $method HTTP method that will be used to send the request.
 * @param  array  $params Parameters for the request defined in an associative array of key-value.
 * @return array          Array of results including HTTP headers or WP_Error if the request failed.
 */
function sucuriscan_api_call( $method='GET', $params=array() ){
    global $wp_version;

    $target_url = SUCURISCAN_API;
    $params[SUCURISCAN_API_VERSION] = 1;

    $req_args = array(
        'method' => $method,
        'httpversion' => '1.0',
        'user-agent' => 'WordPress/' . $wp_version . '; ' . sucuriscan_get_domain(),
        'blocking' => TRUE,
        'headers' => array(),
        'cookies' => array(),
        'compress' => FALSE,
        'decompress' => FALSE,
        'sslverify' => TRUE,
    );

    if( $method == 'GET' ){
        $target_url = sprintf( '%s?%s', $target_url, http_build_query($params) );
        $response = wp_remote_post( $target_url, $req_args );
    }

    elseif( $method == 'POST' ){
        $req_args['body'] = $params;
        $response = wp_remote_post( $target_url, $req_args );
    }

    if( isset($response) ){
        if( is_wp_error($response) ){
            sucuriscan_error( 'Something went wrong with an API call. ' . $response->get_error_message() );
        } else {
            $response['body_raw'] = $response['body'];

            if(
                isset($response['headers']['content-type'])
                && $response['headers']['content-type'] = 'application/json'
            ){
                $response['body'] = json_decode($response['body_raw']);
            }

            return $response;
        }
    }

    return FALSE;
}

/**
 * Store the API key locally.
 *
 * @param  string  $api_key An unique string of characters to identify this installation.
 * @return boolean          Either TRUE or FALSE if the key was saved successfully or not respectively.
 */
function sucuriscan_set_api_key( $api_key='' ){
    return (bool) update_option( 'sucuriscan_api_key', $api_key );
}

/**
 * Retrieve the API key from the local storage.
 *
 * @return string|boolean The API key or FALSE if it does not exists.
 */
function sucuriscan_get_api_key(){
    $api_key = get_option('sucuriscan_api_key');

    if( $api_key && strlen($api_key) > 10 ){
        return $api_key;
    }

    return FALSE;
}

/**
 * Determine whether an API response was successful or not checking the expected
 * generic variables and types, in case of an error a notification will appears
 * in the administrator panel explaining the result of the operation.
 *
 * @param  array   $response Array of results including HTTP headers or WP_Error if the request failed.
 * @return boolean           Either TRUE or FALSE in case of success or failure of the API response (respectively).
 */
function sucuriscan_handle_response( $response=array() ){
    if( $response ){
        if( $response['body'] instanceof stdClass ){
            if( isset($response['body']->status) ){
                if( $response['body']->status == 1 ){
                    return TRUE;
                } else {
                    sucuriscan_error( ucwords($response['body']->action) . ': ' . $response['body']->messages[0] );
                }
            } else {
                sucuriscan_error( 'Could not determine the status of an API call.' );
            }
        } else {
            sucuriscan_error( 'Unknown API content-type, it was not a JSON-encoded response.' );
        }
    } else {
        sucuriscan_error( 'Something went wrong with an API call.' );
    }

    return FALSE;
}

/**
 * Send a request to the API to register this site.
 *
 * @return boolean TRUE if the API key was generated, FALSE otherwise.
 */
function sucuriscan_register_site(){
    $response = sucuriscan_api_call( 'POST', array(
        'e' => sucuriscan_get_site_email(),
        's' => sucuriscan_get_domain(),
        'a' => 'register_site',
        'p' => 'wordpress',
    ) );

    if( sucuriscan_handle_response($response) ){
        sucuriscan_set_api_key( $response['body']->output->api_key );
        sucuriscan_info( 'The API key for your site was successfully generated and saved.');

        return TRUE;
    }

    return FALSE;
}

/**
 * Send a request to the API to store and analyze the events of the site. An
 * event can be anything from a simple request, an internal modification of the
 * settings or files in the administrator panel, or a notification generated by
 * this plugin.
 *
 * @param  string  $event   The information gathered through out the normal functioning of the site.
 * @param  string  $api_key The plugin API key require to communicate with the remote service.
 * @return boolean          TRUE if the event was logged in the monitoring service, FALSE otherwise.
 */
function sucuriscan_send_log( $event='', $api_key='' ){
    if( !empty($event) ){
        if( !$api_key ){
            $api_key = sucuriscan_get_api_key();
        }

        $response = sucuriscan_api_call( 'POST', array(
            'k' => $api_key,
            'a' => 'send_log',
            'p' => 'wordpress',
            'm' => $event,
        ) );

        if( sucuriscan_handle_response($response) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Retrieve the event logs registered by the API service.
 *
 * @param  string $api_key The plugin API key require to communicate with the remote service.
 * @return string          The response of the API service.
 */
function sucuriscan_get_logs( $api_key='' ){
    $response = sucuriscan_api_call( 'GET', array(
        'k' => sucuriscan_get_api_key(),
        'a' => 'get_logs',
        'p' => 'wordpress',
        'l' => 50,
    ) );

    if( sucuriscan_handle_response($response) ){
        $response['body']->output_data = array();
        $log_pattern = '/^([0-9-: ]+) (.*) : (.*)/';

        foreach( $response['body']->output as $log ){
            if( preg_match($log_pattern, $log, $log_match) ){
                $response['body']->output_data[] = array(
                    'datetime' => $log_match[1],
                    'timestamp' => strtotime($log_match[1]),
                    'account' => $log_match[2],
                    'message' => $log_match[3],
                );
            }
        }

        return $response['body'];
    }

    return FALSE;
}

/**
 * Send a request to the API to store and analyze the file's hashes of the site.
 * This will be the core of the monitoring tools and will enhance the
 * information of the audit logs alerting the administrator of suspicious
 * changes in the system.
 *
 * @param  string  $hashes  The information gathered after the scanning of the site's files.
 * @param  string  $api_key The plugin API key require to communicate with the remote service.
 * @return boolean          TRUE if the hashes were stored, FALSE otherwise.
 */
function sucuriscan_send_hashes( $hashes='', $api_key='' ){
    if( !empty($hashes) ){
        if( !$api_key ){
            $api_key = sucuriscan_get_api_key();
        }

        $response = sucuriscan_api_call( 'POST', array(
            'k' => $api_key,
            'a' => 'send_hashes',
            'p' => 'wordpress',
            'h' => $hashes,
        ) );

        if( sucuriscan_handle_response($response) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Checks last time we ran to avoid running twice (or too often).
 *
 * @param  integer $runtime    When the filesystem scan must be scheduled to run.
 * @param  boolean $force_scan Whether the filesystem scan was forced by an administrator user or not.
 * @return boolean             Either TRUE or FALSE representing the success or fail of the operation respectively.
 */
function sucuriscan_verify_run( $runtime=0, $force_scan=FALSE ){
    $runtime_name = 'sucuriscan_runtime';
    $last_run = get_option($runtime_name);
    $current_time = time();

    if( $last_run && !$force_scan ){
        $runtime_diff = $current_time - $runtime;

        if( $last_run >= $runtime_diff ){
            return FALSE;
        }
    }

    update_option( $runtime_name, $current_time );
    return TRUE;
}

/**
 * Check whether the current WordPress version must be reported to the API
 * service or not, this is to avoid duplicated information in the audit logs.
 *
 * @return boolean TRUE if the current WordPress version must be reported, FALSE otherwise.
 */
function sucuriscan_report_wpversion(){
    $option_name = 'sucuriscan_wp_version';
    $reported_version = get_option($option_name);
    $wp_version = sucuriscan_get_wpversion();

    if( $reported_version != $wp_version ){
        sucuriscan_send_log( 'WordPress version: ' . $wp_version );
        update_option( $option_name, $wp_version );

        return TRUE;
    }

    return FALSE;
}

/**
 * Gather all the checksums (aka. file hashes) of this site, send them, and
 * analyze them using the Sucuri Monitoring service, this will generate the
 * audit logs for this site and be part of the integrity checks.
 *
 * @param  boolean $force_scan Whether the filesystem scan was forced by an administrator user or not.
 * @return boolean             TRUE if the filesystem scan was successful, FALSE otherwise.
 */
function sucuriscan_filesystem_scan( $force_scan=FALSE ){
    $minimum_runtime = SUCURISCAN_MINIMUM_RUNTIME;
    $api_key = sucuriscan_get_api_key();

    if(
        $api_key
        && class_exists('SucuriScanFileInfo')
        && sucuriscan_verify_run( $minimum_runtime, $force_scan )
    ){
        sucuriscan_report_wpversion();

        $sucuri_fileinfo = new SucuriScanFileInfo();
        $scan_interface = get_option('sucuriscan_scan_interface');
        $signatures = $sucuri_fileinfo->get_directory_tree_md5(ABSPATH, $scan_interface);

        if( $signatures ){
            $hashes_sent = sucuriscan_send_hashes( $signatures, $api_key );

            if( $hashes_sent ){
                sucuriscan_info( 'Successful filesystem scan' );
                return TRUE;
            } else {
                sucuriscan_error( 'The file hashes could not be stored.' );
            }
        } else {
            sucuriscan_error( 'The file hashes could not be retrieved, the filesystem scan failed.' );
        }
    }

    return FALSE;
}

/**
 * Generates an audit event log (to be sent later).
 *
 * @param  integer $severity Importance of the event that will be reported, values from one to five.
 * @param  string  $location In which part of the system was the event triggered.
 * @param  string  $message  The explanation of the event.
 * @return boolean           TRUE if the event was logged in the monitoring service, FALSE otherwise.
 */
function sucuriscan_report_event( $severity=0, $location='', $message='' ){
    $user = wp_get_current_user();
    $username = 'Unknown user';
    $current_time = date( 'Y-m-d H:i:s' );
    $remote_ip = sucuriscan_get_remoteaddr();

    // Fixing severity value.
    $severity = (int) $severity;
    if( $severity > 0 ){ $severity = 1; }
    elseif( $severity > 5 ){ $severity = 5; }

    // Identify current user in session.
    if( $user instanceof WP_User ){
        $username = sprintf( '%s (%s)', $user->display_name, $user->user_login );
    }

    // Convert the severity number into a readable string.
    switch( $severity ){
        case 0:  $severity_name = 'Debug';    break;
        case 1:  $severity_name = 'Notice';   break;
        case 2:  $severity_name = 'Info';     break;
        case 3:  $severity_name = 'Warning';  break;
        case 4:  $severity_name = 'Error';    break;
        case 5:  $severity_name = 'Critical'; break;
        default: $severity_name = 'Info';     break;
    }

    $message = str_replace( array("\n", "\r"), array('', ''), $message );
    $event_sent = sucuriscan_send_log(sprintf(
        '%s: %s, %s; %s',
        $severity_name, $username, $remote_ip, $message
    ));

    return $event_sent;
}

/**
 * Send a notification to the administrator of the specified events, only if
 * the administrator accepted to receive alerts for this type of events.
 *
 * @param  string $event   The name of the event that was triggered.
 * @param  string $title   Title of the email that will be sent to the administrator.
 * @param  string $content Body of the email that will be sent to the administrator.
 * @return void
 */
function sucuriscan_notify_event( $event='', $content='' ){
    $event_name = 'sucuriscan_notify_' . $event;
    $notify = get_option($event_name);
    $email = sucuriscan_get_option('admin_email');

    if( $notify == 'enabled' ){
        $title = sprintf( 'Sucuri notification (%s)', str_replace('_', chr(32), $event) );
        $mail_sent = sucuriscan_send_mail( $email, $title, $content );

        return $mail_sent;
    }

    return FALSE;
}

$sucuriscan_hooks = array(
    'add_attachment',
    'create_category',
    'delete_post',
    'private_to_published',
    'publish_page',
    'publish_post',
    'publish_phone',
    'xmlrpc_publish_post',
    'add_link',
    'switch_theme',
    'delete_user',
    'retrieve_password',
    'user_register',
    'wp_login',
    'wp_login_failed',
    'login_form_resetpass',
);

/**
 * Send to Sucuri servers an alert advising that an attachment was added to a post.
 *
 * @param  integer $id The post identifier.
 * @return void
 */
function sucuriscan_hook_add_attachment( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );
    $title = ( $data ? $data->post_title : 'Unknown' );

    $message = 'Media file added #'.$id.' ('.$title.')';
    sucuriscan_report_event( 1, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that a category was created.
 *
 * @param  integer $id The identifier of the category created.
 * @return void
 */
function sucuriscan_hook_create_category( $id=0 ){
    $title = ( is_int($id) ? get_cat_name($id) : 'Unknown' );

    $message = 'Category created #'.$id.' ('.$title.')';
    sucuriscan_report_event( 1, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that a post was deleted.
 *
 * @param  integer $id The identifier of the post deleted.
 * @return void
 */
function sucuriscan_hook_delete_post( $id=0 ){
    sucuriscan_report_event( 3, 'core', 'Post deleted #'.$id );
}

/**
 * Send to Sucuri servers an alert advising that the state of a post was changed
 * from private to published. This will only applies for posts not pages.
 *
 * @param  integer $id The identifier of the post changed.
 * @return void
 */
function sucuriscan_hook_private_to_published( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );

    if( $data ){
        $title = $data->post_title;
        $p_type = ucwords($data->post_type);
    } else {
        $title = 'Unknown';
        $p_type = 'Publication';
    }

    $message = $p_type.' changed from private to published #'.$id.' ('.$title.')';
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that a post was published.
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );

    if( $data ){
        $title = $data->post_title;
        $p_type = ucwords($data->post_type);
        $action = ( $data->post_date == $data->post_modified ? 'created' : 'updated' );
    } else {
        $title = 'Unknown';
        $p_type = 'Publication';
        $action = 'published';
    }

    $message = $p_type.' was '.$action.' #'.$id.' ('.$title.')';
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_page( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_post( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_phone( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_xmlrpc_publish_post( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Send to Sucuri servers an alert advising that a new link was added to the bookmarks.
 *
 * @param  integer $id Identifier of the new link created;
 * @return void
 */
function sucuriscan_hook_add_link( $id=0 ){
    $data = ( is_int($id) ? get_bookmark($id) : FALSE );

    if( $data ){
        $title = $data->link_name;
        $url = $data->link_url;
    } else {
        $title = 'Unknown';
        $url = 'undefined/url';
    }

    $message = 'New link added #'.$id.' ('.$title.': '.$url.')';
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that the theme of the site was changed.
 *
 * @param  string $title The name of the new theme selected to used through out the site.
 * @return void
 */
function sucuriscan_hook_switch_theme( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'Theme switched to: '.$title;
    sucuriscan_report_event( 3, 'core', $message );
    sucuriscan_notify_event( 'theme_switched', $message );
}

/**
 * Send to Sucuri servers an alert advising that a user account was deleted.
 *
 * @param  integer $id The identifier of the user account deleted.
 * @return void
 */
function sucuriscan_hook_delete_user( $id=0 ){
    sucuriscan_report_event( 3, 'core', 'User account deleted #'.$id );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to retrieve the password
 * of an user account was tried.
 *
 * @param  string $title The name of the user account involved in the trasaction.
 * @return void
 */
function sucuriscan_hook_retrieve_password( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    sucuriscan_report_event( 3, 'core', 'Password retrieval attempt for user: '.$title );
}

/**
 * Send to Sucuri servers an alert advising that a new user account was created.
 *
 * @param  integer $id The identifier of the new user account created.
 * @return void
 */
function sucuriscan_hook_user_register( $id=0 ){
    $data = ( is_int($id) ? get_userdata($id) : FALSE );
    $title = ( $data ? $data->display_name : 'Unknown' );

    $message = 'New user account registered #'.$id.' ('.$title.')';
    sucuriscan_report_event( 3, 'core', $message );
    sucuriscan_notify_event( 'user_registration', $message );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to login into the
 * administration panel was successful.
 *
 * @param  string $title The name of the user account involved in the transaction.
 * @return void
 */
function sucuriscan_hook_wp_login( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'User logged in: '.$title;
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'success_login', $message );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to login into the
 * administration panel failed.
 *
 * @param  string $title The name of the user account involved in the transaction.
 * @return void
 */
function sucuriscan_hook_wp_login_failed( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'User authentication failed: '.$title;
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'failed_login', $message );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to reset the password
 * of an user account was executed.
 *
 * @return void
 */
function sucuriscan_hook_login_form_resetpass(){
    // Detecting wordpress 2.8.3 vulnerability - $key is array.
    if( isset($_GET['key']) && is_array($_GET['key']) ){
        sucuriscan_report_event( 3, 'core', 'Attempt to reset password by attacking WP/2.8.3 bug' );
    }
}

// Configure the hooks defined above to be triggered automatically.
if( isset($sucuriscan_hooks) ){
    foreach( $sucuriscan_hooks as $hook_name ){
        $hook_func = 'sucuriscan_hook_' . $hook_name;

        if( function_exists($hook_func) ){
            add_action( $hook_name, $hook_func, 50 );
        }
    }
}

if( !function_exists('sucuriscan_hook_undefined_actions') ){

    /**
     * Send a notifications to the administrator of some specific events that are
     * not triggered through an hooked action, but through a simple request in the
     * admin interface.
     *
     * @return integer Either one or zero representing the success or fail of the operation.
     */
    function sucuriscan_hook_undefined_actions(){

        // Plugin activation and/or deactivation.
        if(
            isset($_GET['action'])
            && isset($_GET['plugin'])
            && !empty($_GET['plugin'])
            && ( $_GET['action'] == 'activate' || $_GET['action'] == 'deactivate' )
            && strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== FALSE
            && current_user_can('activate_plugins')
        ){
            $action_d = $_GET['action'] . 'd';
            $message = 'Plugin '.$action_d.': '.esc_attr($_GET['plugin']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'plugin_'.$action_d, $message );
        }

        // Plugin updated.
        elseif(
            isset($_GET['action'])
            && isset($_GET['plugin'])
            && !empty($_GET['plugin'])
            && $_GET['action'] == 'upgrade-plugin'
            && strpos($_SERVER['REQUEST_URI'], 'wp-admin/update.php') !== FALSE
            && current_user_can('update_plugins')
        ){
            $message = 'Plugin request to be updated: '.esc_attr($_GET['plugin']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'plugin_updated', $message );
        }

        // Plugin installation request.
        elseif(
            isset($_GET['action'])
            && preg_match('/^(install|upload)-plugin$/', $_GET['action'])
            && current_user_can('install_plugins')
        ){
            if( isset($_FILES['pluginzip']) ){
                $plugin = $_FILES['pluginzip']['name'];
            } elseif( isset($_GET['plugin']) ){
                $plugin = $_GET['plugin'];
            } else {
                $plugin = 'Unknown';
            }

            $message = 'Plugin request to be installed: ' . esc_attr($plugin);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'plugin_installed', $message );
        }

        // Plugin deletion request.
        elseif(
            isset($_POST['action'])
            && $_POST['action'] == 'delete-selected'
            && isset($_POST['verify-delete'])
            && $_POST['verify-delete'] == 1
            && current_user_can('delete_plugins')
        ){
            $plugin = '';
            $plugins = isset($_POST['checked']) ? $_POST['checked'] : array();

            if( is_array($plugins) && !empty($plugins) ){
                $separator = ','.chr(32);
                foreach($plugins as $plugin_path){
                    $plugin .= basename($plugin_path).$separator;
                }
                $plugin = rtrim($plugin, $separator);
            }

            $message = 'Plugin request to be deleted: ' . esc_attr($plugin);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'plugin_deleted', $message );
        }

        // WordPress update request.
        elseif(
            isset($_POST['upgrade'])
            && isset($_POST['version'])
            && strpos($_SERVER['REQUEST_URI'], 'update-core.php?action=do-core-reinstall') !== FALSE
            && current_user_can('update_core')
        ){
            $message = 'WordPress updated (or re-installed) to version: ' . esc_attr($_POST['version']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'website_updated', $message );
        }

        // Theme editor request.
        elseif(
            isset($_POST['action'])
            && $_POST['action'] == 'update'
            && isset($_POST['file'])
            && isset($_POST['theme'])
            && strpos($_SERVER['REQUEST_URI'], 'theme-editor.php') !== FALSE
        ){
            $message = 'Theme editor modification: ' . esc_attr($_POST['theme']) . '/' . esc_attr($_POST['file']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'theme_editor', $message );
        }

        // Plugin editor request.
        elseif(
            isset($_POST['action'])
            && $_POST['action'] == 'update'
            && isset($_POST['file'])
            && isset($_POST['plugin'])
            && strpos($_SERVER['REQUEST_URI'], 'plugin-editor.php') !== FALSE
        ){
            $message = 'Plugin editor modification: ' . esc_attr($_POST['file']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'theme_editor', $message );
        }

        // Detect any Wordpress settings modification.
        elseif( isset($_POST['option_page']) ){
            // Get the settings available in the database and compare them with the submission.
            $all_options = sucuriscan_get_wp_options();
            $options_changed = sucuriscan_what_options_were_changed($_POST);

            // Generate the list of options changed.
            $options_changed_str = '';
            foreach( $options_changed['original'] as $option_name => $option_value ){
                $options_changed_str .= sprintf(
                    "The value of the option <b>%s</b> was changed from <b>'%s'</b> to <b>'%s'</b>.<br>\n",
                    $option_name, $option_value, $options_changed['changed'][$option_name]
                );
            }

            // Notify via email that these options were modified.
            $page_referer = FALSE;
            $option_page = isset($_POST['option_page']) ? $_POST['option_page'] : 'options';

            switch( $option_page ){
                case 'options':
                    $page_referer = 'Global';
                    break;
                case 'general':    /* no_break */
                case 'writing':    /* no_break */
                case 'reading':    /* no_break */
                case 'discussion': /* no_break */
                case 'media':      /* no_break */
                case 'permalink':
                    $page_referer = ucwords($option_page);
                    break;
                default:
                    $page_referer = 'Common';
                    break;
            }

            if( $page_referer ){
                $message = $page_referer.' settings changed';
                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'settings_updated', $message . "<br>\n" . $options_changed_str );
            }
        }

    }

    add_action( 'admin_init', 'sucuriscan_hook_undefined_actions' );
    add_action( 'login_form', 'sucuriscan_hook_undefined_actions' );
}

/**
 * Print a HTML code with the content of the logs audited by the remote Sucuri
 * API service, this page is part of the monitoring tool.
 *
 * @return void
 */
function sucuriscan_auditlogs_page(){

    $api_key = sucuriscan_get_api_key();
    $max_per_page = SUCURISCAN_AUDITLOGS_PER_PAGE;
    $audit_logs = $api_key ? sucuriscan_get_logs($api_key) : FALSE;
    $show_all = isset($_GET['show_all']) ? TRUE : FALSE;

    $template_variables = array(
        'PageTitle' => 'Audit Logs',
        'AuditLogs.List' => '',
        'AuditLogs.Count' => 0,
        'AuditLogs.NoItemsVisibility' => 'visible',
        'AuditLogs.MaxItemsVisibility' => 'hidden',
        'AuditLogs.MaxPerPage' => $max_per_page,
    );

    if( $audit_logs ){
        $counter = 0;
        $total_items = count($audit_logs->output_data);

        $template_variables['AuditLogs.Count'] = $total_items;
        $template_variables['AuditLogs.NoItemsVisibility'] = 'hidden';

        if( $total_items > $max_per_page && !$show_all ){
            $template_variables['AuditLogs.MaxItemsVisibility'] = 'visible';
        }

        foreach( $audit_logs->output_data as $audit_log ){
            if( $counter > $max_per_page && !$show_all ){ break; }

            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

            $template_variables['AuditLogs.List'] .= sucuriscan_get_snippet('auditlogs', array(
                'AuditLog.CssClass' => $css_class,
                'AuditLog.DateTime' => date( 'd/M/Y H:i:s', $audit_log['timestamp'] ),
                'AuditLog.Account' => $audit_log['account'],
                'AuditLog.Message' => $audit_log['message'],
            ));
            $counter += 1;
        }
    }

    echo sucuriscan_get_template('auditlogs', $template_variables);
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
            sucuriscan_harden_removegenerator();
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
        'PageTitle' => '(1-Click Hardening)',
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
function sucuriscan_harden_removegenerator(){
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

    $template_variables = array(
        'PageTitle' => 'WordPress Integrity',
        'CoreFiles' => sucuriscan_core_files(),
        'ModifiedFiles' => sucuriscan_modified_files(),
        'AdminUsers' => sucuriscan_admin_users(),
        'PluginList' => sucuriscan_plugin_list(),
        'ThemeList' => sucuriscan_theme_list(),
    );

    echo sucuriscan_get_template('integrity', $template_variables);
}

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
function sucuriscan_core_files(){
    global $wp_version;

    $cp = 0;
    $updates = get_core_updates();

    if(
        !is_array($updates)
        || empty($updates)
        || $updates[0]->response=='latest'
    ){
        $cp = 1;
    }

    if( strcmp($wp_version, '3.7') < 0 ){
        $cp = 0;
    }

    $template_variables = array(
        'WordPress.Version' => $wp_version,
        'WordPress.UpgradeURL' => admin_url('update-core.php'),
        'WordPress.UpdateVisibility' => 'hidden',
        'CoreFiles.Visibility' => 'hidden',
        'CoreFiles.Added' => '',
        'CoreFiles.Removed' => '',
        'CoreFiles.Modified' => '',
    );

    $wp_version = htmlspecialchars($wp_version);

    if( $cp == 0 ){
        $template_variables['WordPress.UpdateVisibility'] = 'visible';
    } else {
        $latest_hashes = sucuriscan_check_wp_integrity($wp_version);

        if( $latest_hashes ){
            $template_variables['CoreFiles.Visibility'] = 'visible';
            $list = array(
                'added' => $latest_hashes['added'],
                'removed' => $latest_hashes['removed'],
                'modified' => $latest_hashes['bad']
            );

            foreach( $list as $list_id=>$file_list ){
                $i_name = 'CoreFiles.'.ucwords($list_id);
                $i_name_count = $i_name.'Count';
                $template_variables[$i_name_count] = sizeof($file_list);

                if( !empty($file_list) ){
                    $counter = 0;

                    foreach( $file_list as $file_path ){
                        $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                        $template_variables[$i_name] .= sucuriscan_get_snippet('integrity-corefiles', array(
                            'CoreFiles.CssClass' => $css_class,
                            'CoreFiles.FilePath' => $file_path
                        ));
                        $counter += 1;
                    }
                } else {
                    $template_variables[$i_name] .= sucuriscan_get_snippet('integrity-corefiles', array(
                        'CoreFiles.CssClass' => '',
                        'CoreFiles.FilePath' => '<em>Empty list.</em>'
                    ));
                }
            }
        }else{
            sucuriscan_admin_notice('error', 'Error retrieving the wordpress core hashes, try again.');
        }
    }

    return sucuriscan_get_section('integrity-corefiles', $template_variables);
}

/**
 * List all files inside wp-content that have been modified in the last days.
 *
 * @return void
 */
function sucuriscan_modified_files(){
    $noncek = 'sucuriscan_modified_files';
    $valid_day_ranges = array( 1, 3, 7, 30, 60 );
    $template_variables = array(
        'ModifiedFiles.Nonce' => wp_create_nonce($noncek),
        'ModifiedFiles.List' => '',
        'ModifiedFiles.SelectOptions' => '',
        'ModifiedFiles.NoFilesVisibility' => 'visible',
        'ModifiedFiles.Days' => 0,
    );

    // Find files modified in the last days.
    $back_days = 1;

    // Correct the ranges of the search to be between one and sixty days.
    if( isset($_POST['sucuriscan_last_days']) ){
        if( !isset($_POST[$noncek]) || !wp_verify_nonce($_POST[$noncek], $noncek) ){
            wp_die(__('Invalid form submission.') );
        }

        $back_days = intval($_POST['sucuriscan_last_days']);
        if    ( $back_days <= 0  ){ $back_days = 1;  }
        elseif( $back_days >= 60 ){ $back_days = 60; }
    }

    // Generate the options for the select field of the page form.
    foreach( $valid_day_ranges as $day ){
        $selected_option = ($back_days == $day) ? 'selected="selected"' : '';
        $template_variables['ModifiedFiles.SelectOptions'] .= sprintf(
            '<option value="%d" %s>%d</option>',
            $day, $selected_option, $day
        );
    }

    // Scan the files of the site.
    $template_variables['ModifiedFiles.Days'] = $back_days;
    $wp_content_hashes = read_dir_r( ABSPATH.'wp-content', true );
    $back_days = current_time('timestamp') - ( $back_days * 86400);
    $counter = 0;

    foreach( $wp_content_hashes as $file_path=>$file_info ){
        if( $file_info['time'] >= $back_days ){
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
            $mod_date = date('d/M/Y H:i:s', $file_info['time']);

            $template_variables['ModifiedFiles.List'] .= sucuriscan_get_snippet('integrity-modifiedfiles', array(
                'ModifiedFiles.CssClass' => $css_class,
                'ModifiedFiles.CheckSum' => $file_info['md5'],
                'ModifiedFiles.FilePath' => $file_path,
                'ModifiedFiles.DateTime' => $mod_date
            ));
            $counter += 1;
        }
    }

    if( $counter > 0 ){
        $template_variables['ModifiedFiles.NoFilesVisibility'] = 'hidden';
    }

    return sucuriscan_get_section('integrity-modifiedfiles', $template_variables);
}

/**
 * List all the user administrator accounts.
 *
 * @see http://codex.wordpress.org/Class_Reference/WP_User_Query
 *
 * @return void
 */
function sucuriscan_admin_users(){
    // Page pseudo-variables initialization.
    $template_variables = array(
        'AdminUsers.List' => ''
    );

    $user_query = new WP_User_Query(array( 'role' => 'Administrator' ));
    $admins = $user_query->get_results();

    foreach( (array)$admins as $admin ){
        $admin->lastlogins = sucuriscan_get_logins(5, $admin->ID);

        $user_snippet = array(
            'AdminUsers.Username' => $admin->user_login,
            'AdminUsers.Email' => $admin->user_email,
            'AdminUsers.LastLogins' => '',
            'AdminUsers.UserURL' => admin_url('user-edit.php?user_id='.$admin->ID),
            'AdminUsers.NoLastLogins' => 'visible',
            'AdminUsers.NoLastLoginsTable' => 'hidden',
        );

        if( !empty($admin->lastlogins) ){
            $user_snippet['AdminUsers.NoLastLogins'] = 'hidden';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'visible';
            $counter = 0;

            foreach( $admin->lastlogins as $lastlogin ){
                $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                $user_snippet['AdminUsers.LastLogins'] .= sucuriscan_get_snippet('integrity-admins-lastlogin', array(
                    'AdminUsers.RemoteAddr' => $lastlogin->user_remoteaddr,
                    'AdminUsers.Datetime' => $lastlogin->user_lastlogin,
                    'AdminUsers.CssClass' => $css_class,
                ));
                $counter += 1;
            }
        }

        $template_variables['AdminUsers.List'] .= sucuriscan_get_snippet('integrity-admins', $user_snippet);
    }

    return sucuriscan_get_section('integrity-admins', $template_variables);
}

/**
 * Check if any installed plugin an update available.
 *
 * @return void
 */
function sucuriscan_plugin_list(){
    $template_variables = array(
        'AddonList.Items' => '',
        'AddonList.UpToDateVisibility' => 'visible',
    );

    // Check plugins.
    do_action('wp_update_plugins');
    wp_update_plugins();
    $update_plugins = get_site_transient('update_plugins');
    $plugins_need_update = (bool) !empty($update_plugins->response);

    if( $plugins_need_update ){
        $counter = 0;
        $template_variables['AddonList.UpToDateVisibility'] = 'hidden';

        foreach( $update_plugins->response as $rel_path => $plugin_info ){
            $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $rel_path );
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
            $counter += 1;

            $template_variables['AddonList.Items'] .= sucuriscan_get_snippet('integrity-addonlist', array(
                'AddonList.CssClass' => $css_class,
                'AddonList.Title' => $plugin_data['Title'],
                'AddonList.Version' => $plugin_data['Version'],
                'AddonList.NewVersion' => $plugin_info->new_version,
                'AddonList.Package' => $plugin_info->package,
            ));
        }
    }

    return sucuriscan_get_section('integrity-addonlist', $template_variables);
}

/**
 * Check if any installed theme has an update available.
 *
 * @return void
 */
function sucuriscan_theme_list(){
    $template_variables = array(
        'AddonList.Items' => '',
        'AddonList.UpToDateVisibility' => 'visible',
    );

    // Check themes.
    do_action('wp_update_themes');
    wp_update_themes();
    $update_themes = get_theme_updates();
    $themes_need_update = (bool) !empty($update_themes);

    if( $themes_need_update ){
        $counter = 0;
        $template_variables['AddonList.UpToDateVisibility'] = 'hidden';

        foreach( $update_themes as $stylesheet => $theme ){
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
            $counter += 1;

            $template_variables['AddonList.Items'] .= sucuriscan_get_snippet('integrity-addonlist', array(
                'AddonList.CssClass' => $css_class,
                'AddonList.Title' => $theme->display('Name'),
                'AddonList.Version' => $theme->display('Version'),
                'AddonList.NewVersion' => $theme->update['new_version'],
                'AddonList.Package' => $theme->update['package'],
            ));
        }
    }

    return sucuriscan_get_section('integrity-addonlist', $template_variables);
}

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
        'PageTitle' => 'Post-Hack',
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
        $user->user_registered_timestamp = strtotime($user->user_registered);
        $user->user_registered_formatted = date('D, M/Y H:i', $user->user_registered_timestamp);
        $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

        $user_snippet = sucuriscan_get_snippet('resetpassword', array(
            'ResetPassword.UserId' => $user->ID,
            'ResetPassword.Username' => $user->user_login,
            'ResetPassword.Displayname' => $user->display_name,
            'ResetPassword.Email' => $user->user_email,
            'ResetPassword.Registered' => $user->user_registered_formatted,
            'ResetPassword.Roles' => implode(', ', $user->roles),
            'ResetPassword.CssClass' => $css_class
        ));

        $template_variables['ResetPassword.UserList'] .= $user_snippet;
        $counter += 1;
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
        'PageTitle' => 'Last Logins',
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
    foreach( $user_list as $user ){
        $counter += 1;
        $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';

        $user_dataset = array(
            'UserList.Number' => $counter,
            'UserList.UserId' => $user->user_id,
            'UserList.Username' => '<em>Unknown</em>',
            'UserList.Displayname' => '',
            'UserList.Email' => '',
            'UserList.Registered' => '',
            'UserList.RemoteAddr' => $user->user_remoteaddr,
            'UserList.Hostname' => $user->user_hostname,
            'UserList.Datetime' => $user->user_lastlogin,
            'UserList.TimeAgo' => sucuriscan_time_ago($user->user_lastlogin),
            'UserList.UserURL' => admin_url('user-edit.php?user_id='.$user->user_id),
            'UserList.CssClass' => $css_class,
            'UserList.Username' => '',
            'UserList.Displayname' => '',
            'UserList.Email' => '',
            'UserList.Registered' => '',
        );

        if( $user->user_exists ){
            $user_dataset['UserList.Username'] = $user->user_login;
            $user_dataset['UserList.Displayname'] = $user->display_name;
            $user_dataset['UserList.Email'] = $user->user_email;
            $user_dataset['UserList.Registered'] = $user->user_registered;
        }

        $template_variables['UserList'] .= sucuriscan_get_snippet('lastlogins', $user_dataset);
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
                $user_lastlogin['user_exists'] = FALSE;
                $user_account = get_userdata($user_lastlogin['user_id']);

                if( $user_account ){
                    $user_lastlogin['user_exists'] = TRUE;

                    foreach( $user_account->data as $var_name=>$var_value ){
                        $user_lastlogin[$var_name] = $var_value;
                    }
                }

                $lastlogins[] = (object)$user_lastlogin;
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
    function sucuriscan_login_redirect( $redirect_to='', $request=NULL, $user=FALSE ){
        $login_url = !empty($redirect_to) ? $redirect_to : admin_url();

        if( $user instanceof WP_User && $user->ID ){
            $login_url = add_query_arg( 'sucuriscan_lastlogin_message', 1, $login_url );
        }

        return $login_url;
    }

    $lastlogin_redirection = sucuriscan_get_option('sucuriscan_lastlogin_redirection');
    if( $lastlogin_redirection == 'enabled' ){
        add_filter('login_redirect', 'sucuriscan_login_redirect', 10, 3);
    }
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
        'PageTitle' => 'Site Info',
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
 * Gather information from the server, database engine, and PHP interpreter.
 *
 * @return array A list of pseudo-variables and values that will replace them in the HTML template.
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
            'SettingsDisplay' => 'block',
            'PluginVersion' => SUCURISCAN_VERSION,
            'PluginMD5' => md5_file(SUCURISCAN_PLUGIN_FILEPATH),
            'PluginRuntimeDatetime' => $plugin_runtime_datetime,
            'OperatingSystem' => sprintf('%s (%d Bit)', PHP_OS, PHP_INT_SIZE*8),
            'Server' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'MemoryUsage' => $memory_usage,
            'MySQLVersion' => $mysql_version,
            'SQLMode' => $sql_mode,
            'PHPVersion' => PHP_VERSION,
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
 * Global variables used by the functions bellow.
 *
 * These are lists of options allowed to use in the execution of the monitoring
 * tool, and the administrator can select among them in the settings page.
 *
 * @var array
 */
$sucuriscan_notify_options = array(
    'sucuriscan_notify_user_registration' => 'Enable new user registration alerts',
    'sucuriscan_notify_success_login' => 'Enable successful logins alerts',
    'sucuriscan_notify_failed_login' => 'Enable failed logins alerts',
    'sucuriscan_notify_post_publication' => 'Enable new site content alerts',
    'sucuriscan_notify_theme_editor' => 'Enable when any file is modified via the editor alerts',
    'sucuriscan_notify_website_updated' => 'Enable email notifications when your website is updated',
    'sucuriscan_notify_settings_updated' => 'Enable email notifications when your website settings are updated',
    'sucuriscan_notify_theme_switched' => 'Enable email notifications when the website theme is switched',
    'sucuriscan_notify_plugin_change' => 'Enable Sucuri plugin changes alerts',
    'sucuriscan_notify_plugin_activated' => 'Enable email notifications when a plugin is activated',
    'sucuriscan_notify_plugin_deactivated' => 'Enable email notifications when a plugin is deactivated',
    'sucuriscan_notify_plugin_updated' => 'Enable email notifications when a plugin is updated',
    'sucuriscan_notify_plugin_installed' => 'Enable email notifications when a plugin is installed',
    'sucuriscan_notify_plugin_deleted' => 'Enable email notifications when a plugin is deleted',
    'sucuriscan_prettify_mails' => 'Enable HTML notifications (uncheck if you want to receive notifications in text plain)',
    'sucuriscan_lastlogin_redirection' => 'Allow redirection after login to report the last-login information (uncheck if you have custom redirection rules)',
);

$sucuriscan_schedule_allowed = array(
    'hourly' => 'Every three hours (3 hours)',
    'twicedaily' => 'Twice daily (12 hours)',
    'daily' => 'Once daily (24 hours)',
    '_oneoff' => 'Never',
);

$sucuriscan_interface_allowed = array(
    'spl' => 'SPL (Standard PHP Library)',
    'opendir' => 'OpenDir (Medium performance)',
    'glob' => 'Glob (Low performance)',
);

/**
 * Print a HTML code with the settings of the plugin.
 *
 * @return void
 */
function sucuriscan_settings_page(){

    global $sucuriscan_schedule_allowed, $sucuriscan_interface_allowed, $sucuriscan_notify_options;

    // Process all form submissions.
    sucuriscan_settings_form_submissions();

    // Get initial variables to decide some things bellow.
    $api_key = sucuriscan_get_api_key();
    $scan_freq = sucuriscan_get_option('sucuriscan_scan_frequency');
    $scan_interface = sucuriscan_get_option('sucuriscan_scan_interface');
    $runtime_scan = sucuriscan_get_option('sucuriscan_runtime');
    $runtime_scan_human = date( 'd/M/Y H:i:s', $runtime_scan );

    // Generate HTML code to configure the scanning frequency from the plugin settings.
    $scan_freq_options = '';
    foreach( $sucuriscan_schedule_allowed as $schedule => $schedule_label ){
        $selected = ( $scan_freq==$schedule ? 'selected="selected"' : '' );
        $scan_freq_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $schedule, $selected, $schedule_label
        );
    }

    // Generate HTML code to configure the scanning interface from the plugin settings.
    $scan_interface_options = '';
    foreach( $sucuriscan_interface_allowed as $interface_name => $interface_desc ){
        $selected = ( $scan_interface==$interface_name ? 'selected="selected"' : '' );
        $scan_interface_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $interface_name, $selected, $interface_desc
        );
    }

    // Generate HTML code to configure the notifications of the plugin.
    $notification_options = '';
    $counter = 0;

    foreach( $sucuriscan_notify_options as $alert_type => $alert_label ){
        $alert_value = sucuriscan_get_option($alert_type);
        $checked = ( $alert_value == 'enabled' ? 'checked="checked"' : '' );
        $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

        $notification_options .= sucuriscan_get_snippet('settings-notification', array(
            'Notification.CssClass' => $css_class,
            'Notification.Name' => $alert_type,
            'Notification.Checked' => $checked,
            'Notification.Label' => $alert_label,
        ));
        $counter += 1;
    }

    $template_variables = array(
        'APIKey' => $api_key,
        'APIKey.RemoveVisibility' => ( $api_key ? 'visible' : 'hidden' ),
        'ScanningFrequency' => ( $scan_freq ? $scan_freq : 'Undefined' ),
        'ScanningFrequencyOptions' => $scan_freq_options,
        'ScanningInterface' => ( $scan_interface ? $scan_interface : 'Undefined' ),
        'ScanningInterfaceOptions' => $scan_interface_options,
        'ScanningRuntime' => $runtime_scan,
        'ScanningRuntimeHuman' => $runtime_scan_human,
        'NotificationOptions' => $notification_options,
    );

    echo sucuriscan_get_template('settings', $template_variables);
}

/**
 * Process the requests sent by the form submissions originated in the settings
 * page, all forms must have a nonce field that will be checked agains the one
 * generated in the template render function.
 *
 * @return void
 */
function sucuriscan_settings_form_submissions(){

    global $sucuriscan_schedule_allowed, $sucuriscan_interface_allowed, $sucuriscan_notify_options;

    if( sucuriscan_check_page_nonce() ){

        // Register the site, get its API key, and store it locally for future usage.
        if( isset($_POST['sucuriscan_get_api_key']) ){
            $key_generated = sucuriscan_register_site();

            // Schedule a job to execute the filesystem scan.
            if( $key_generated ){
                if( !wp_next_scheduled('sucuriscan_scheduled_scan') ){
                    wp_schedule_event( time() + 10, 'twicedaily', 'sucuriscan_scheduled_scan' );
                }

                wp_schedule_single_event( time() + 300, 'sucuriscan_scheduled_scan' );
                sucuriscan_notify_event( 'plugin_change', 'Site registered and API key generated' );
                sucuriscan_info( 'The first filesystem scan was scheduled.' );
            }
        }

        // Remove API key from the local storage.
        if( isset($_POST['sucuriscan_remove_api_key']) ){
            sucuriscan_set_api_key('');
            wp_clear_scheduled_hook('sucuriscan_scheduled_scan');
            sucuriscan_notify_event( 'plugin_change', 'Sucuri API key removed' );
        }

        // Modify the schedule of the filesystem scanner.
        if(
            isset($_POST['sucuriscan_scan_frequency'])
            && isset($sucuriscan_schedule_allowed)
        ){
            $frequency = $_POST['sucuriscan_scan_frequency'];
            $current_frequency = sucuriscan_get_option('sucuriscan_scan_frequency');
            $allowed_frequency = array_keys($sucuriscan_schedule_allowed);

            if( in_array($frequency, $allowed_frequency) && $current_frequency != $frequency ){
                update_option('sucuriscan_scan_frequency', $frequency);
                wp_clear_scheduled_hook('sucuriscan_scheduled_scan');

                if( $frequency != '_oneoff' ){
                    wp_schedule_event( time()+10, $frequency, 'sucuriscan_scheduled_scan' );
                }

                sucuriscan_notify_event( 'plugin_change', 'Filesystem scanning frequency changed to: ' . $frequency );
                sucuriscan_info( 'Filesystem scan scheduled to run <code>'.$frequency.'</code>' );
            }
        }

        // Set the method (aka. interface) that will be used to scan the site.
        if(
            isset($_POST['sucuriscan_scan_interface'])
            && isset($sucuriscan_interface_allowed)
        ){
            $interface = trim($_POST['sucuriscan_scan_interface']);
            $allowed_values = array_keys($sucuriscan_interface_allowed);

            if( in_array($interface, $allowed_values) ){
                update_option('sucuriscan_scan_interface', $interface);
                sucuriscan_notify_event( 'plugin_change', 'Filesystem scanning interface changed to: ' . $interface );
                sucuriscan_info( 'Filesystem scan interface set to <code>'.$interface.'</code>' );
            }
        }

        // Manually force a filesystem scan (by an administrator user).
        if( isset($_POST['sucuriscan_force_scan']) ){
            if( current_user_can('manage_options') ){
                sucuriscan_notify_event( 'plugin_change', 'Filesystem scan forced at: ' . date('r') );
                sucuriscan_filesystem_scan(TRUE);
            } else {
                sucuriscan_error( 'Your privileges are not sufficient to execute this action.' );
            }
        }

        // Update the notification settings.
        if(
            isset($_POST['sucuriscan_save_notification_settings'])
            && isset($sucuriscan_notify_options)
        ){
            foreach( $sucuriscan_notify_options as $alert_type => $alert_label ){
                if( isset($_POST[$alert_type]) ){
                    $option_value = ( $_POST[$alert_type] == 1 ? 'enabled' : 'disabled' );
                    update_option( $alert_type, $option_value );
                    sucuriscan_notify_event( 'plugin_change', 'Email notification settings changed' );
                }
            }

            sucuriscan_info( 'Notification settings updated.' );
        }

    }

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

    $template_variables = array(
    	'PageTitle' => 'About'
    );

    echo sucuriscan_get_template('about', $template_variables);
}

