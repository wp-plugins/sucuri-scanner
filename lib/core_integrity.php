<?php
/* Sucuri Security - WordPress Core Intherity check against the latest version
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */
if(!defined('SUCURISCAN'))
{
    return(0);
}

function read_dir_r($dir = "./", $recursiv = false)
{
    $skipname  = basename(__FILE__);
    $skipname .= ",_sucuribackup,wp-config.php";

    $files_info = array();

    $dir_handler = opendir($dir);

    while(($entry = readdir($dir_handler)) !== false) {
      if ($entry != "." && $entry != "..") {
          $dir = preg_replace("/^(.*)(\/)+$/", "$1", $dir);
          $item = $dir . "/" . $entry;
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

function sucuriwp_core_integrity_check()
{

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
        echo '<p><img style="position:relative;top:5px" height="22" width="22" '
             .'src="'.SUCURI_URL.'images/warn.png" /> &nbsp; Your current version ('.$wp_version.') is not the latest. '
             .'<a class="button-primary" href="update-core.php">Update now!</a> to be able to run the integrity check.</p>';
    }
    else
    {
        $latest_hashes = @file_get_contents("http://wordpress.sucuri.net/wp_core_latest_hashes.json");
        if($latest_hashes){
            $wp_core_latest_hashes = json_decode($latest_hashes, true);

            $wp_includes_hashes = read_dir_r( ABSPATH . "wp-includes", true);
            $wp_admin_hashes = read_dir_r( ABSPATH . "wp-admin", true);
            $wp_top_hashes = read_dir_r( ABSPATH , false);

            $wp_core_hashes = array_merge( $wp_includes_hashes , $wp_admin_hashes );
            $wp_core_hashes = array_merge( $wp_core_hashes , $wp_top_hashes );

            $added = @array_diff_assoc( $wp_core_hashes, $wp_core_latest_hashes ); //files added
            $removed = @array_diff_assoc( $wp_core_latest_hashes, $wp_core_hashes ); //files deleted
            unset($removed['wp_version']); //ignore wp_version key
            $compcurrent = @array_diff_key( $wp_core_hashes, $added ); //remove all added files from current filelist
            $complog = @array_diff_key( $wp_core_latest_hashes, $removed );  //remove all deleted files from old file list
            $modified = array(); //array of modified files

            //compare file hashes and mod dates
            foreach ( $compcurrent as $currfile => $currattr) {

                if ( array_key_exists( $currfile, $complog ) ) {

                    //if attributes differ added to modified files array
                    if ( strcmp( $currattr['md5'], $complog[$currfile]['md5'] ) != 0 ) {
                        $modified[$currfile]['md5'] = $currattr['md5'];
                    }

                }

            }

            //ignore some junk files
            if($curlang != "en_US")
            {
                //ignore added files
                unset($added['./licencia.txt']);

                //ignore removed files
                unset($removed['./license.txt']);

                //ignore modified files
                unset($modified['./wp-includes/version.php']);
                unset($modified['./wp-admin/setup-config.php']);
                unset($modified['./readme.html']);
                unset($modified['./wp-config-sample.php']);
            }

            sucuriscan_draw_corefiles_status(array(
                'added'=>$added,
                'removed'=>$removed,
                'modified'=>$modified
            ));
        }else{
            sucuriscan_admin_notice('error', 'Error retrieving the wordpress core hashes, try again.');
        }
    }
}

function sucuriscan_draw_corefiles_status($list=array()){
    if( is_array($list) && !empty($list) ): ?>
        <table class="wp-list-table widefat sucuriscan-corefiles">
            <thead>
                <tr><th>Core files altered</th></tr>
            </thead>
            <tbody>
                <?php
                foreach($list as $core_file_type=>$core_file_list){
                    printf('<tr><th>Core File %s: %d</th></tr>', ucwords($core_file_type), sizeof($core_file_list));
                    foreach($core_file_list as $filepath=>$extrainfo){
                        printf('<tr><td>%s</td></tr>', $filepath);
                    }
                }
                ?>
            </tbody>
        </table>
    <?php endif; ?>
<?php }

function sucuriwp_list_admins($userlevel = '10') {

    global $wpdb;
    /*
     1 = subscriber
     2 = editor
     3 = author
     7 = publisher
    10 = administrator
    */

    // Page pseudo-variables initialization.
    $template_variables = array(
        'SucuriURL'=>SUCURI_URL,
        'AdminUsers.UserList'=>''
    );

    $admins = $wpdb->get_results("SELECT DISTINCT(user_id) AS user_id FROM `$wpdb->usermeta` WHERE meta_value = '$userlevel'");
    foreach ( (array) $admins as $user ) {
        $admin    = get_userdata( $user->user_id );
        $admin->lastlogins = sucuriscan_get_logins(4, $admin->ID);
        $userlevel = $admin->wp2_user_level;
        $name      = $admin->nickname;

        $user_snippet = array(
            'AdminUsers.Username'=>$admin->user_login,
            'AdminUsers.Email'=>$admin->user_email,
            'AdminUsers.LastLogins'=>'',
            'AdminUsers.UserURL'=>admin_url('user-edit.php?user_id='.$user->user_id)
        );
        if( !empty($admin->lastlogins) ){
            $user_snippet['AdminUsers.NoLastLogins'] = 'hidden';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'visible';
            foreach($admin->lastlogins as $lastlogin){
                $user_snippet['AdminUsers.LastLogins'] .= sucuriscan_get_template('integrity-admins-lastlogin.snippet.tpl', array(
                    'AdminUsers.RemoteAddr'=>$lastlogin->user_remoteaddr,
                    'AdminUsers.Datetime'=>$lastlogin->user_lastlogin
                ));
            }
        }else{
            $user_snippet['AdminUsers.NoLastLogins'] = 'visible';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'hidden';
        }

        $template_variables['AdminUsers.UserList'] .= sucuriscan_get_template('integrity-admins.snippet.tpl', $user_snippet);
    }

    echo sucuriscan_get_template('integrity-admins.html.tpl', $template_variables);
}

function sucuriwp_check_plugins()
{
    do_action("wp_update_plugins"); // force WP to check plugins for updates
    wp_update_plugins();
    $update_plugins = get_site_transient('update_plugins'); // get information of updates
    $plugins_need_update = $update_plugins->response; // plugins that need updating

     echo '<div class="postbox">';
        echo "<h3>Outdated Plugins</h3>";
        echo '<div class="inside">';
        if (!empty($update_plugins->response)) { // any plugin updates available?
            $plugins_need_update = $update_plugins->response; // plugins that need updating
            $active_plugins = array_flip(get_option('active_plugins')); // find which plugins are active
            $plugins_need_update = array_intersect_key($plugins_need_update, $active_plugins); // only keep plugins that are active
            if(count($plugins_need_update) >= 1) { // any plugins need updating after all the filtering gone on above?
                require_once(ABSPATH . 'wp-admin/includes/plugin-install.php'); // Required for plugin API
                require_once(ABSPATH . WPINC . '/version.php' ); // Required for WP core version
                foreach($plugins_need_update as $key => $data) { // loop through the plugins that need updating
                    $plugin_info = get_plugin_data(WP_PLUGIN_DIR . "/" . $key); // get local plugin info
                    $info = plugins_api('plugin_information', array('slug' => $data->slug )); // get repository plugin info
                    $message = "\n".sprintf(__("Plugin: %s is out of date. Please update from version %s to %s", "wp-updates-notifier"), $plugin_info['Name'], $plugin_info['Version'], $data->new_version)."\n";
                    echo "<p>$message</p>";
                }
            }
            else
            {
                echo "<p>All plugins are up-to-date!</p>";
            }
        }
        else
        {
            echo "<p>All plugins are up-to-date!</p>";
        }
        echo '</div>';
    echo '</div>';
}

function sucuriwp_check_themes()
{
    do_action("wp_update_themes"); // force WP to check for theme updates
    wp_update_themes();
    $update_themes = get_site_transient('update_themes'); // get information of updates

    echo '<div class="postbox">';
        echo "<h3>Outdated Themes</h3>";
        echo '<div class="inside">';
            if (!empty($update_themes->response)) { // any theme updates available?
                $themes_need_update = $update_themes->response; // themes that need updating

                if(count($themes_need_update) >= 1) { // any themes need updating after all the filtering gone on above?
                    foreach($themes_need_update as $key => $data) { // loop through the themes that need updating
                        $theme_info = get_theme_data(WP_CONTENT_DIR . "/themes/" . $key . "/style.css"); // get theme info
                        $message = sprintf(__("Theme: %s is out of date. Please update from version %s to %s", "wp-updates-notifier"), $theme_info['Name'], $theme_info['Version'], $data['new_version'])."\n";
                       echo "<p>$message</p>";
                    }
                }
            }
            else
            {
                echo "<p>All themes are up-to-date!</p>";
            }
        echo '</div>';
    echo '</div>';
}
