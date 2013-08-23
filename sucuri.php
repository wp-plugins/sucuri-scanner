<?php
/*
Plugin Name: Sucuri Security - SiteCheck Malware Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: The <a href="http://sucuri.net">Sucuri Security</a> - SiteCheck Malware Scanner plugin enables you to <strong>scan your WordPress site using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a></strong> right in your WordPress dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.

You can also scan your site at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Author: Sucuri Security
Version: 1.4.4
Author URI: http://sucuri.net
*/

/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

define('SUCURISCAN','sucuriscan');
define('SUCURISCAN_VERSION','1.4.4');
define( 'SUCURI_URL',plugin_dir_url( __FILE__ ));
define('SUCURISCAN_PLUGIN_FOLDER', 'sucuri-scanner');
/* Sucuri Free/Paid Plugin will use the same tablename, check: sucuriscan_lastlogins_table_exists() */
define('SUCURISCAN_LASTLOGINS_TABLENAME', "{$table_prefix}sucuri_lastlogins");

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
}

/* Sucuri malware scan page. */

function sucuri_scan_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }

    if(isset($_POST['wpsucuri-doscan']))
    {
        sucuriscan_print_scan();
        return(1);
    }

    /* Setting's header. */
    echo '<div class="wrap">';
        echo '<h2 id="warnings_hook"></h2>';
        echo '<div class="sucuriscan_header"><img src="'.SUCURI_URL.'/inc/images/logo.png">';
        sucuriscan_pagestop("SiteCheck Scanner");
        echo '</div>';

        echo '<div class="postbox-container" style="width:75%;">';
            echo '<div class="sucuriscan-maincontent">';

            echo '<div class="postbox">';
               echo '<div class="inside">';
                   echo '<h2 align="center">Scan your site for malware using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a> right in your WordPress dashboard.</h2>';
               echo '</div>';
            echo '</div>';
        ?>

                <form action="" method="post">
                    <input type="hidden" name="wpsucuri-doscan" value="wpsucuri-doscan" />
                    <input class="button button-primary button-hero load-customize" type="submit" name="wpsucuri_doscanrun" value="Scan this site now!" />
                </form>

                <p><strong>If you have any questions about these checks or this plugin, contact us at <a href="mailto:info@sucuri.net">info@sucuri.net</a> or visit <a href="http://sucuri.net">sucuri.net</a></strong></p>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sucuri-wp-sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

function sucuriscan_print_scan()
{
    $myresults = wp_remote_get("http://sitecheck.sucuri.net/scanner/?serialized&clear&fromwp&scan=".home_url(), array("timeout" => 180));

    if(is_wp_error($myresults))
    {
        print_r($myresults);
        return;
    }

    $res = unserialize($myresults['body']);

    echo '<div class="wrap">';
    echo '<h2 id="warnings_hook"></h2>';
    echo '<div class="sucuriscan_header"><img src="'.SUCURI_URL.'/inc/images/logo.png">';
    sucuriscan_pagestop("Sucuri SiteCheck Malware Scanner");
    echo '</div>';

        echo '<div class="postbox-container" style="width:75%;">';
            echo '<div class="sucuriscan-maincontent">';

    if(!isset($res['MALWARE']['WARN']))
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
             '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
             No malware was identified</h3>';

        echo "<p><strong>Malware:</strong> No.</p>";
        echo "<p><strong>Malicious javascript:</strong> No.</p>";
        echo "<p><strong>Malicious iframes:</strong> No.</p>";
        echo "<p><strong>Suspicious redirections (htaccess):</strong> No.</p>";
        echo "<p><strong>Blackhat SEO Spam:</strong> No.</p>";
        echo "<p><strong>Anomaly detection:</strong> Clean.</p>";
    }
    else
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
             '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
             Site compromised (malware was identified)</h3>';
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
        echo "<br />";
    }
    echo '<i>More details here: <a href="http://sitecheck.sucuri.net/scanner/?&scan='.home_url().'">http://sitecheck.sucuri.net/scanner/?&scan='.home_url().'</a></i>';

    echo "<hr />\n";
    echo '<i>If our free scanner did not detect any issue, you may have a more complicated and hidden problem. You can try our <a href="admin.php?page=sucuriscan_core_integrity">WordPress integrity checks</a> or sign up with Sucuri <a target="_blank" href="http://sucuri.net/signup">here</a> for a complete and in depth scan+cleanup (not included in the free checks).</i>';
    echo "<hr />\n";
    if(isset($res['BLACKLIST']['WARN']))
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
                 '.site_url().'/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp;
                 Site blacklisted</h3>';
    }
    else
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
                 '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
                 Site blacklist-free</h3>';
    }
    if(isset($res['BLACKLIST']['INFO']))
    {
        foreach($res['BLACKLIST']['INFO'] as $blres)
        {
            echo "<b>CLEAN: </b>".htmlspecialchars($blres[0])." <a href=''>".htmlspecialchars($blres[1])."</a><br />";
        }
    }
    if(isset($res['BLACKLIST']['WARN']))
    {
        foreach($res['BLACKLIST']['WARN'] as $blres)
        {
            echo "<b>WARN: </b>".htmlspecialchars($blres[0])." <a href=''>".htmlspecialchars($blres[1])."</a><br />";
        }
    }

    echo "<hr />\n";
    global $wp_version;
    if(strcmp($wp_version, "3.5") >= 0)
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
                 '.site_url().'/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp;
                 System info (WordPress upgraded)</h3>';
    }
    else
    {
        echo '<h3><img style="position:relative;top:5px" height="22" width="22" src="
                 '.site_url().'/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp;
                 System info (WordPress outdated)</h3>';
    }

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

    ?>
                <p>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></p>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sucuri-wp-sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri Header Function */

function sucuriscan_pagestop($sucuri_title = 'Sucuri Plugin')
{
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
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
    echo '<div class="sucuriscan_header"><img src="'.SUCURI_URL.'/inc/images/logo.png">';
    sucuriscan_pagestop("Sucuri 1-Click Hardening Options");
    echo '</div>';

    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }

    include_once("sucuriscan_hardening.php");

    sucuriscan_hardening_lib()

    ?>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sucuri-wp-sidebar.html.tpl') ?>

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri WordPress Integrity page. */

function sucuriscan_core_integrity_page()

{

    /* WordPress Integrity page. */

    echo '<div class="wrap">';
    echo '<h2 id="warnings_hook"></h2>';
    echo '<div class="sucuriscan_header"><img src="'.SUCURI_URL.'/inc/images/logo.png">';
    sucuriscan_pagestop("Sucuri WordPress Integrity");
    echo '</div>';

    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }

    include_once("sucuriscan_core_integrity.php");

    sucuriscan_core_integrity_lib()

    ?>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->

        <?php echo sucuriscan_get_template('sucuri-wp-sidebar.html.tpl') ?>

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

    return sucuriscan_get_template("sucuri-wp-notification.{$prettify_type}.tpl", $mail_variables);
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
    return sucuriscan_get_template('sucuri-wp-sidebar.html.tpl');
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
        wp_die(__('You do not have sufficient permissions to access this page.') );
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
            wp_die(__('Wordpress Nonce verification failed, try again going back and checking the form.') );
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
                    $user_identifiers = $_POST['user_ids'];
                    $pwd_changed = $pwd_not_changed = array();
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
        $user_snippet = sucuriscan_get_template('sucuri-wp-resetpassword.snippet.tpl', array(
            'ResetPassword.UserId'=>$user->ID,
            'ResetPassword.Username'=>$user->user_login,
            'ResetPassword.Displayname'=>$user->display_name,
            'ResetPassword.Email'=>$user->user_email
        ));
        $template_variables['ResetPassword.UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('sucuri-wp-posthack.html.tpl', $template_variables);
}

function sucuriscan_lastlogins_page()
{
    if( !current_user_can('manage_options') )
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'PosthackNonce'=>wp_create_nonce('sucuri_posthack_nonce'),
        'SucuriWPSidebar'=>sucuriscan_wp_sidebar_gen(),
        'UserList'=>'',
        'CurrentURL'=>site_url().'/wp-admin/admin.php?page='.$_GET['page']
    );

    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : 10;
    $template_variables['UserList.ShowAll'] = $limit>0 ? 'display:table' : 'display:none';

    $user_list = sucuriscan_get_logins($limit);
    foreach($user_list as $user){
        $user_snippet = sucuriscan_get_template('sucuri-wp-lastlogins.snippet.tpl', array(
            'UserList.UserId'=>$user->ID,
            'UserList.Username'=>$user->user_login,
            'UserList.Email'=>$user->user_email,
            'UserList.RemoteAddr'=>$user->user_remoteaddr,
            'UserList.Datetime'=>$user->user_lastlogin
        ));
        $template_variables['UserList'] .= $user_snippet;
    }

    echo sucuriscan_get_template('sucuri-wp-lastlogins.html.tpl', $template_variables);
}

if( !function_exists('sucuri_login_redirect') ){
    function sucuri_login_redirect(){
        return admin_url('?sucuri_lastlogin_message=1');
    }
    add_filter('login_redirect', 'sucuri_login_redirect');
}

function sucuriscan_get_flashdata()
{
    if( isset($_GET['sucuri_lastlogin_message']) ){
        $remote_addr = sucuriscan_get_remoteaddr();
        $lastlogin_message  = 'Last user login at <strong>'.date('Y/M/d H:i:s').'</strong>';
        $lastlogin_message .= chr(32).'from <strong>'.$remote_addr.' - '.gethostbyaddr($remote_addr).'</strong>';
        if( isset($_SERVER['GEOIP_REGION']) && isset($_SERVER['GEOIP_CITY']) ){
            $lastlogin_message .= chr(32)."{$_SERVER['GEOIP_CITY']}/{$_SERVER['GEOIP_REGION']}";
        }
        $lastlogin_message .= chr(32).'(<a href="'.site_url('wp-admin/admin.php?page=sucuriscan_lastlogins').'">View Last-Logins</a>)';

        sucuriscan_admin_notice('updated', $lastlogin_message);
    }
}
add_action('admin_notices', 'sucuriscan_get_flashdata');

function sucuriscan_get_remoteaddr()
{
    $alternatives = array(
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    );
    foreach($alternatives as $alternative){
        if( !isset($_SERVER[$alternative]) ){ continue; }

        $remote_addr = preg_replace('/[^0-9., ]/', '', $_SERVER[$alternative]);
        if($remote_addr) break;
    }

    return $remote_addr;
}

function sucuriscan_lastlogins_table_exists()
{
    global $wpdb;
    if( defined('SUCURISCAN_LASTLOGINS_TABLENAME') ){
        $table_name = SUCURISCAN_LASTLOGINS_TABLENAME;

        if( $wpdb->get_var("SHOW TABLES LIKE '{$table_name}'")!=$table_name ){
            $sql = 'CREATE TABLE '.$table_name.' (
                id int(11) NOT NULL AUTO_INCREMENT,
                user_id bigint(20) NOT NULL,
                user_login varchar(60),
                user_remoteaddr varchar(255),
                user_lastlogin DATETIME DEFAULT "0000-00-00 00:00:00" NOT NULL,
                UNIQUE KEY id(id)
            )';

            require_once(ABSPATH.'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }
    }
}
add_action('plugins_loaded', 'sucuriscan_lastlogins_table_exists');

function sucuriscan_set_lastlogin($user_login='')
{
    global $wpdb;
    if( defined('SUCURISCAN_LASTLOGINS_TABLENAME') ){
        $table_name = SUCURISCAN_LASTLOGINS_TABLENAME;
        $current_user = get_user_by('login', $user_login);
        $remote_addr = sucuriscan_get_remoteaddr();

        $wpdb->insert($table_name, array(
            'user_id'=>$current_user->ID,
            'user_login'=>$current_user->user_login,
            'user_remoteaddr'=>$remote_addr,
            'user_lastlogin'=>current_time('mysql')
        ));
    }
}
add_action('wp_login', 'sucuriscan_set_lastlogin', 50);

function sucuriscan_get_logins($limit=10, $user_id=0)
{
    global $wpdb;
    if( defined('SUCURISCAN_LASTLOGINS_TABLENAME') ){
        $table_name = SUCURISCAN_LASTLOGINS_TABLENAME;

        $sql = "SELECT * FROM {$table_name} LEFT JOIN {$wpdb->prefix}users ON {$table_name}.user_id = {$wpdb->prefix}users.ID";
        if( !is_admin() ){
            $current_user = wp_get_current_user();
            $sql .= chr(32)."WHERE {$wpdb->prefix}users.user_login = '{$current_user->user_login}'";
        }
        if( $user_id>0 ){
            $where_append = strpos('WHERE ', $sql)===FALSE ? 'WHERE' : 'AND';
            $sql .= chr(32)."{$where_append} {$table_name}.user_id = '{$user_id}'";
        }
        $sql .= chr(32)."ORDER BY {$table_name}.id DESC";
        if( preg_match('/^([0-9]+)$/', $limit) && $limit>0 ){
            $sql .= chr(32)."LIMIT {$limit}";
        }
        return $wpdb->get_results($sql);
    }

    return FALSE;
}
