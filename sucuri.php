<?php
/*
Plugin Name: Sucuri Security - SiteCheck Malware Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: The <a href="http://sucuri.net">Sucuri Security</a> - SiteCheck Malware Scanner plugin enables you to <strong>scan your WordPress site using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a></strong> right in your WordPress dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.

You can also scan your site at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Author: Sucuri, INC
Version: 1.5.4
Author URI: http://sucuri.net
*/

/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

define('SUCURISCAN','sucuriscan');
define('SUCURISCAN_VERSION','1.5.4');
define('SUCURI_URL',plugin_dir_url( __FILE__ ));
define('SUCURISCAN_PLUGIN_FILE', 'sucuri.php');
define('SUCURISCAN_PLUGIN_FOLDER', 'sucuri-scanner');
define('SUCURISCAN_PLUGIN_PATH', WP_PLUGIN_DIR.'/'.SUCURISCAN_PLUGIN_FOLDER);
define('SUCURISCAN_PLUGIN_FILEPATH', SUCURISCAN_PLUGIN_PATH.'/'.SUCURISCAN_PLUGIN_FILE);

define('SUCURISCAN_LASTLOGINS_USERSLIMIT', 100);

if( !function_exists('sucuriscan_create_uploaddir') ){
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

/* Requires files. */
add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );
function sucuriscan_admin_script_style_registration() { ?>
    <link rel="stylesheet" href="<?php echo SUCURI_URL; ?>/inc/css/sucuriscan-default-css.css" type="text/css" media="all" />
    <script type="text/javascript">
    function sucuriscan_alert_close(id){
        var element = document.getElementById('sucuri-alert-'+id);
        element.parentNode.removeChild(element);
    }
    </script>
<?php }

/* sucuri_dir_filepath:
 * Returns the system filepath to the relevant user uploads
 * directory for this site. Multisite capable.
 */
function sucuriscan_dir_filepath($path = '')
{
    $wp_dir_array = wp_upload_dir();
    $wp_dir_array['basedir'] = untrailingslashit($wp_dir_array['basedir']);
    return($wp_dir_array['basedir']."/sucuri/$path");
}

/* Starting Sucuri Scan side bar. */
function sucuriscan_menu()
{
    add_menu_page('Sucuri Free', 'Sucuri Free', 'manage_options',
                  'sucuriscan', 'sucuri_scan_page', SUCURI_URL.'images/menu-icon.png');
    add_submenu_page('sucuriscan', 'Sucuri Scanner', 'Sucuri Scanner', 'manage_options',
                     'sucuriscan', 'sucuri_scan_page');

    add_submenu_page('sucuriscan', '1-click Hardening', '1-click Hardening', 'manage_options',
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

/* Sucuri malware scan page. */

function sucuri_scan_page()
{
    $U_ERROR = NULL;
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Malware Scanner') );
    }

    $template_variables = array(
        'PluginURL'=>SUCURI_URL,
        'Sidebar'=>sucuriscan_get_template('sidebar.html.tpl')
    );

    if( isset($_POST['wpsucuri-doscan']) ){
        sucuriscan_print_scan();
        return(1);
    }

    echo sucuriscan_get_template('initial-page.html.tpl', $template_variables);
}

function sucuriscan_print_scan()
{
    $website_scanned = home_url();
    $myresults = wp_remote_get('http://sitecheck.sucuri.net/scanner/?serialized&clear&fromwp&scan='.$website_scanned, array('timeout' => 180));

    echo '<div class="wrap">';
        echo '<h2 id="warnings_hook"></h2>';
        echo '<div class="sucuriscan_header">';
        echo '<a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security">';
        echo '<img src="'.SUCURI_URL.'/inc/images/logo.png" alt="Sucuri Security" />';
        echo '</a>';
        sucuriscan_pagestop("Sucuri SiteCheck Malware Scanner");
        echo '</div>';

        echo '<div class="postbox-container" style="width:75%;">';
            echo '<div class="sucuriscan-maincontent">';

                if(is_wp_error($myresults))
                {
                    echo '<div id="poststuff">';
                        echo '<div class="postbox">';
                            echo '<h3>Error retrieving the scan report</h3>';

                            echo '<div class="inside">';
                                print_r($myresults);
                            echo '</div>';
                        echo '</div>';
                    echo '</div>';
                }else if( preg_match('/^ERROR:/', $myresults['body']) ){
                    sucuriscan_admin_notice('error', $myresults['body'].' The URL scanned was: <code>'.$website_scanned.'</code>');
                }else{
                    $res = unserialize($myresults['body']);


                    // Check for general warnings, and return the information for Infected/Clean site.
                    $malware_warns_exists = isset($res['MALWARE']['WARN']) ? TRUE : FALSE;
                    echo '<div id="poststuff">';
                        echo '<div class="postbox">';
                            echo '<h3>';
                                if( !$malware_warns_exists ){
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                         '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
                                         No malware was identified';
                                }else{
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                         '.site_url().'/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp;
                                         Site compromised (malware was identified)';
                                }
                            echo '</h3>';
                            echo '<div class="inside">';
                                if( !$malware_warns_exists ){
                                    echo "<span><strong>Malware:</strong> No.</span><br>";
                                    echo "<span><strong>Malicious javascript:</strong> No.</span><br>";
                                    echo "<span><strong>Malicious iframes:</strong> No.</span><br>";
                                    echo "<span><strong>Suspicious redirections (htaccess):</strong> No.</span><br>";
                                    echo "<span><strong>Blackhat SEO Spam:</strong> No.</span><br>";
                                    echo "<span><strong>Anomaly detection:</strong> Clean.</span><br>";
                                }else{
                                    foreach($res['MALWARE']['WARN'] as $malres)
                                    {
                                        if(!is_array($malres))
                                        {
                                            echo htmlspecialchars($malres);
                                        }
                                        else
                                        {
                                            $mwdetails = explode("\n", htmlspecialchars($malres[1]));
                                            echo htmlspecialchars($malres[0])."\n<br />". substr($mwdetails[0], 1)."<br />\n";
                                        }
                                    }
                                }
                                echo "<br />";
                                echo '<i>More details here: <a href="http://sitecheck.sucuri.net/scanner/?scan='.$website_scanned.'">http://sitecheck.sucuri.net/scanner/?scan='.$website_scanned.'</a></i>';
                                echo "<hr />\n";
                                echo '<i>If our free scanner did not detect any issue, you may have a more complicated and hidden problem. You can try our <a href="admin.php?page=sucuriscan_core_integrity">WordPress integrity checks</a> or sign up with Sucuri <a target="_blank" href="http://sucuri.net/signup">here</a> for a complete and in depth scan+cleanup (not included in the free checks).</i>';
                                echo "<hr />\n";
                            echo '</div>';
                        echo '</div>';
                    echo '</div>';


                    // Check for blacklist reports, and return the information retrieved from multiple blacklist services.
                    echo '<div id="poststuff">';
                        echo '<div class="postbox">';
                            echo '<h3>';
                                if(isset($res['BLACKLIST']['WARN']))
                                {
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                        '.site_url().'/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp;
                                        Site blacklisted';
                                }
                                else
                                {
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                        '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
                                        Site blacklist-free';
                                }
                            echo '</h3>';
                            echo '<div class="inside">';
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
                            echo '</div>';
                        echo '</div>';
                    echo '</div>';


                    // Check for general versions in some common services/software used to serve this website.
                    global $wp_version;
                    $wordpress_updated = FALSE;
                    $updates = function_exists('get_core_updates') ? get_core_updates() : array();
                    if( !is_array($updates) || empty($updates) || $updates[0]->response=='latest' ){
                        $wordpress_updated = TRUE;
                    }

                    echo '<div id="poststuff">';
                        echo '<div class="postbox">';
                            echo '<h3>';
                                if($wordpress_updated)
                                {
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                        '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
                                        System info (WordPress upgraded)';
                                }
                                else
                                {
                                    echo '<img style="position:relative;top:5px" height="22" width="22" src="
                                        '.site_url().'/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp;
                                        System info (WordPress outdated)';
                                }
                            echo '</h3>';
                            echo '<div class="inside">';
                                echo "<b>Site:</b> ".$res['SCAN']['SITE'][0]." (".$res['SCAN']['IP'][0].")<br />\n";
                                echo "<b>WordPress: </b> $wp_version<br />\n";
                                echo "<b>PHP: </b> ".phpversion()."<br />\n";
                                if(isset($res['SYSTEM']['NOTICE']))
                                {
                                    foreach($res['SYSTEM']['NOTICE'] as $notres)
                                    {
                                        if(is_array($notres))
                                        {
                                            echo htmlspecialchars($notres[0]). " ".htmlspecialchars($notres[1]);
                                        }
                                        else
                                        {
                                            echo htmlspecialchars($notres)."<br />\n";
                                        }
                                    }
                                }
                            echo '</div>';
                        echo '</div>';
                    echo '</div>';
                }
                ?>

                <p>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></p>
            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri Header Function */

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

/* Sucuri one-click hardening page. */

function sucuriscan_hardening_page()

{

    /* Hardening page. */

    echo '<div class="wrap">';
    echo '<h2 id="warnings_hook"></h2>';
    echo '<div class="sucuriscan_header">';
    echo '<a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security">';
    echo '<img src="'.SUCURI_URL.'/inc/images/logo.png" alt="Sucuri Security" />';
    echo '</a>';
    sucuriscan_pagestop("Sucuri 1-Click Hardening Options");
    echo '</div>';

    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Hardening') );
    }

    include_once("sucuriscan_hardening.php");

    sucuriscan_hardening_lib()

    ?>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri WordPress Integrity page. */

function sucuriscan_core_integrity_page()

{

    /* WordPress Integrity page. */

    echo '<div class="wrap">';
    echo '<h2 id="warnings_hook"></h2>';
    echo '<div class="sucuriscan_header">';
    echo '<a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security">';
    echo '<img src="'.SUCURI_URL.'/inc/images/logo.png" alt="Sucuri Security" />';
    echo '</a>';
    sucuriscan_pagestop("Sucuri WordPress Integrity");
    echo '</div>';

    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Integrity Check') );
    }

    include_once("sucuriscan_core_integrity.php");

    sucuriscan_core_integrity_lib()

    ?>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri's admin menu. */

add_action('admin_menu', 'sucuriscan_menu');
remove_action('wp_head', 'wp_generator');

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

function sucuriscan_get_template($template='', $template_variables=array()){
    $template_content = '';
    $template_path =  WP_PLUGIN_DIR.'/'.SUCURISCAN_PLUGIN_FOLDER."/inc/tpl/{$template}";

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);
        foreach($template_variables as $tpl_key=>$tpl_value){
            $template_content = str_replace("%%SUCURI.{$tpl_key}%%", $tpl_value, $template_content);
        }
    }
    return $template_content;
}

function sucuriscan_wp_sidebar_gen()
{
    return sucuriscan_get_template('sidebar.html.tpl');
}

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

function sucuriscan_posthack_page()
{
    if( !current_user_can('manage_options') )
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Post-Hack') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'PosthackNonce'=>wp_create_nonce('sucuri_posthack_nonce'),
        'SucuriWPSidebar'=>sucuriscan_wp_sidebar_gen(),
        'WPConfigUpdate.Display'=>'display:none',
        'WPConfigUpdate.NewConfig'=>'',
        'ResetPassword.UserList'=>''
    );

    // Process form submission
    if( isset($_POST['sucuri_posthack_action']) ){
        if( !wp_verify_nonce($_POST['sucuri_posthack_nonce'], 'sucuri_posthack_nonce') )
        {
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
    $user_list = get_users();
    foreach($user_list as $user){
        $user_snippet = sucuriscan_get_template('resetpassword.snippet.tpl', array(
            'ResetPassword.UserId'=>$user->ID,
            'ResetPassword.Username'=>$user->user_login,
            'ResetPassword.Displayname'=>$user->display_name,
            'ResetPassword.Email'=>$user->user_email
        ));
        $template_variables['ResetPassword.UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('posthack.html.tpl', $template_variables);
}

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

        $remote_addr = preg_replace('/[^0-9., ]/', '', $_SERVER[$alternative]);
        if($remote_addr) break;
    }

    return $remote_addr;
}

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
 * Sucuri Scanner - Last Logins
 * @return Functions associated to the Last Logins page.
 */

function sucuriscan_lastlogins_page()
{
    if( !current_user_can('manage_options') )
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'LastLoginsNonce'=>wp_create_nonce('sucuriscan_lastlogins_nonce'),
        'SucuriWPSidebar'=>sucuriscan_wp_sidebar_gen(),
        'UserList'=>'',
        'CurrentURL'=>site_url().'/wp-admin/admin.php?page='.$_GET['page'],
    );

    if( !sucuriscan_lastlogins_datastore_is_writable() ){
        sucuriscan_admin_notice('error', '<strong>Error.</strong> The last-logins datastore
            file is not writable, gives permissions to write in this location:<br>'.
            '<code>'.sucuriscan_lastlogins_datastore_filepath().'</code>');
    }

    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : SUCURISCAN_LASTLOGINS_USERSLIMIT;
    $template_variables['UserList.ShowAll'] = $limit>0 ? 'visible' : 'hidden';

    $user_list = sucuriscan_get_logins($limit);
    foreach($user_list as $user){
        $user_snippet = sucuriscan_get_template('lastlogins.snippet.tpl', array(
            'UserList.UserId'=>intval($user->ID),
            'UserList.Username'=>( !is_null($user->user_login) ? $user->user_login : '<em>Unknown</em>' ),
            'UserList.Email'=>$user->user_email,
            'UserList.RemoteAddr'=>$user->user_remoteaddr,
            'UserList.Datetime'=>$user->user_lastlogin
        ));
        $template_variables['UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('lastlogins.html.tpl', $template_variables);
}

function sucuriscan_lastlogins_datastore_filepath(){
    $plugin_upload_folder = sucuriscan_dir_filepath();
    $datastore_filepath = rtrim($plugin_upload_folder,'/').'/sucuri-lastlogins.php';
    return $datastore_filepath;
}

function sucuriscan_lastlogins_datastore_exists(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_filepath();

    if( !file_exists($datastore_filepath) ){
        if( @file_put_contents($datastore_filepath, "<?php exit(0); ?>\n", LOCK_EX) ){
            @chmod($datastore_filepath, 0644);
        }
    }

    return file_exists($datastore_filepath) ? $datastore_filepath : FALSE;
}

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

function sucuriscan_lastlogins_datastore_is_readable(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_exists();
    if( $datastore_filepath && is_readable($datastore_filepath) ){
        return $datastore_filepath;
    }
    return FALSE;
}

if( !function_exists('sucuri_set_lastlogin') ){
    function sucuriscan_set_lastlogin($user_login=''){
        $datastore_filepath = sucuriscan_lastlogins_datastore_is_writable();

        if($datastore_filepath){
            $current_user = get_user_by('login', $user_login);
            $remote_addr = sucuriscan_get_remoteaddr();

            $login_info = array(
                'user_id'=>$current_user->ID,
                'user_login'=>$current_user->user_login,
                'user_remoteaddr'=>$remote_addr,
                'user_hostname'=>@gethostbyaddr($remote_addr),
                'user_lastlogin'=>current_time('mysql')
            );

            @file_put_contents($datastore_filepath, serialize($login_info)."\n", FILE_APPEND);
        }
    }
    add_action('wp_login', 'sucuriscan_set_lastlogin', 50);
}

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
 * Sucuri Scanner - Info System
 * @return Functions associated to the Info System page.
 */

function sucuriscan_is_multisite(){
    if( function_exists('is_multisite') && is_multisite() ){ return TRUE; }
    return FALSE;
}


function sucuriscan_get_wpconfig_path(){
    $wp_config_path = ABSPATH.'wp-config.php';

    // if wp-config.php doesn't exist/not readable check one directory up
    if( !is_readable($wp_config_path)){
        $wp_config_path = ABSPATH.'/../wp-config.php';
    }
    return $wp_config_path;
}


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


function sucuriscan_infosys_page(){
    if( !current_user_can('manage_options') )
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'SucuriWPSidebar'=>sucuriscan_wp_sidebar_gen(),
        'CurrentURL'=>site_url().'/wp-admin/admin.php?page='.$_GET['page']
    );

    $template_variables['LoggedInUsers'] = sucuriscan_infosys_loggedin();
    $template_variables['HTAccessIntegrity'] = sucuriscan_infosys_htaccess();
    $template_variables['WordpressConfig'] = sucuriscan_infosys_wpconfig();

    echo sucuriscan_get_template('infosys.html.tpl', $template_variables);
}


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

    return sucuriscan_get_template('infosys-htaccess.html.tpl', $template_variables);
}


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


function sucuriscan_infosys_wpconfig(){
    $template_variables = array(
        'WordpressConfig.Rules' => '',
        'WordpressConfig.Total' => 0,
        'WordpressConfig.Content' => '',
    );
    $ignore_wp_rules = array('DB_PASSWORD');

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
                $line = str_replace(');', '', $line);
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
        foreach( $wp_config_rules as $var_name=>$var_value ){
            $template_variables['WordpressConfig.Total'] += 1;
            $template_variables['WordpressConfig.Rules'] .= sucuriscan_get_template('infosys-wpconfig.snippet.tpl', array(
                'WordpressConfig.VariableName' => $var_name,
                'WordpressConfig.VariableValue' => htmlentities($var_value),
            ));
        }
    }

    return sucuriscan_get_template('infosys-wpconfig.html.tpl', $template_variables);
}


function sucuriscan_infosys_loggedin(){
    // Get user logged in list.
    $template_variables = array(
        'LoggedInUsers.List' => '',
        'LoggedInUsers.Total' => 0,
    );

    $logged_in_users = sucuriscan_get_online_users();
    if( is_array($logged_in_users) && !empty($logged_in_users) ){
        $template_variables['LoggedInUsers.Total'] = count($logged_in_users);

        foreach( (array)$logged_in_users as $logged_in_user ){
            $logged_in_user['last_activity_datetime'] = date('d/M/Y H:i', $logged_in_user['last_activity']);
            $logged_in_user['user_registered_datetime'] = date('d/M/Y H:i', strtotime($logged_in_user['user_registered']));

            $template_variables['LoggedInUsers.List'] .= sucuriscan_get_template('infosys-loggedin.snippet.tpl', array(
                'LoggedInUsers.Id' => $logged_in_user['user_id'],
                'LoggedInUsers.UserURL' => admin_url('user-edit.php?user_id='.$logged_in_user['user_id']),
                'LoggedInUsers.UserLogin' => $logged_in_user['user_login'],
                'LoggedInUsers.UserEmail' => $logged_in_user['user_email'],
                'LoggedInUsers.LastActivity' => $logged_in_user['last_activity_datetime'],
                'LoggedInUsers.Registered' => $logged_in_user['user_registered_datetime'],
                'LoggedInUsers.RemoveAddr' => $logged_in_user['remote_addr'],
            ));
        }
    }

    return sucuriscan_get_template('infosys-loggedin.html.tpl', $template_variables);
}


function sucuriscan_get_online_users(){
    if( sucuriscan_is_multisite() ){
        return get_site_transient('online_users');
    }else{
        return get_transient('online_users');
    }
}


function sucuriscan_save_online_users($logged_in_users=array()){
    $expiration = 30 * 60;
    if( sucuriscan_is_multisite() ){
        return set_site_transient('online_users', $logged_in_users, $expiration);
    }else{
        return set_transient('online_users', $logged_in_users, $expiration);
    }
}


if( !function_exists('sucuriscan_unset_online_user_on_logout') ){
    function sucuriscan_unset_online_user_on_logout(){
        $current_user = wp_get_current_user();
        $user_id = $current_user->ID;
        $remote_addr = sucuriscan_get_remoteaddr();

        sucuriscan_unset_online_user($user_id, $remote_addr);
    }

    add_action('wp_logout', 'sucuriscan_unset_online_user_on_logout');
}

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
 * Sucuri Scanner - About page
 * @return Functions associated to the About page.
 */

function sucuriscan_about_page()
{
    if( !current_user_can('manage_options') )
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'SucuriWPSidebar'=>sucuriscan_wp_sidebar_gen(),
        'CurrentURL'=>site_url().'/wp-admin/admin.php?page='.$_GET['page'],
        'SettingsDisplay'=>'hidden'
    );

    $template_variables = sucuriscan_about_information($template_variables);
    $template_variables = sucuriscan_show_cronjobs($template_variables);

    echo sucuriscan_get_template('about.html.tpl', $template_variables);
}

function sucuriscan_about_information($template_variables=array())
{
    global $wpdb;

    if( current_user_can('manage_options') ){
        $memory_usage = function_exists('memory_get_usage') ? round(memory_get_usage()/1024/1024,2).' MB' : 'N/A';
        $mysql_version = $wpdb->get_var('SELECT VERSION() AS version');
        $mysql_info = $wpdb->get_results('SHOW VARIABLES LIKE "sql_mode"');
        $sql_mode = ( is_array($mysql_info) && !empty($mysql_info[0]->Value) ) ? $mysql_info[0]->Value : 'Not set';
        $plugin_runtime_filepath = sucuriscan_dir_filepath('.runtime');
        $plugin_runtime_datetime = file_exists($plugin_runtime_filepath) ? date('r',filemtime($plugin_runtime_filepath)) : 'N/A';

        $template_variables = array_merge($template_variables, array(
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
        ));

        foreach(array(
            'safe_mode',
            'allow_url_fopen',
            'memory_limit',
            'upload_max_filesize',
            'post_max_size',
            'max_execution_time',
            'max_input_time',
        ) as $php_flag){
            $php_flag_name = ucwords(str_replace('_', chr(32), $php_flag) );
            $tpl_varname = str_replace(chr(32), '', $php_flag_name);
            $php_flag_value = ini_get($php_flag);
            $template_variables[$tpl_varname] = $php_flag_value ? $php_flag_value : 'N/A';
        }
    }

    return $template_variables;
}

function sucuriscan_show_cronjobs($template_variables=array())
{
    $template_variables['Cronjobs'] = '';

    $cronjobs = _get_cron_array();
    $schedules = wp_get_schedules();
    $date_format = _x('M j, Y - H:i', 'Publish box date format', 'cron-view' );

    foreach( $cronjobs as $timestamp=>$cronhooks ){
        foreach( (array)$cronhooks as $hook=>$events ){
            foreach( (array)$events as $key=>$event ){
                $cronjob_snippet = '';
                $template_variables['Cronjobs'] .= sucuriscan_get_template('about-cronjobs.snippet.tpl', array(
                    'Cronjob.Task'=>ucwords(str_replace('_',chr(32),$hook)),
                    'Cronjob.Schedule'=>$event['schedule'],
                    'Cronjob.Nexttime'=>date_i18n($date_format, $timestamp),
                    'Cronjob.Hook'=>$hook,
                    'Cronjob.Arguments'=>implode(', ', $event['args'])
                ));
            }
        }
    }

    return $template_variables;
}
