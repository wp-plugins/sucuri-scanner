<?php
/* Sucuri Security WordPress Plugin
 * Copyright (C) 2011 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */


if(!defined('SUCURISCAN'))
{
    exit(0);
}

if(!function_exists('file_put_contents'))
{
    exit(0);
}


if(isset($_POST['wpscansucuri-doharden']) && 
   !wp_verify_nonce($_POST['sucuriscan-harden-action'],'sucuriscan-nonce'))
{
   echo '<div id="message" class="error"><p>Internal error. Please try again.</p></div>';
   return;
}


function sucuriscan_harden_error($message)
{
    return('<div id="message" class="error"><p>'.$message.'</p></div>');
}


function sucuriscan_harden_ok($message)
{
    return( '<div id="message" class="updated"><p>'.$message.'</p></div>');
}


function sucuriscan_harden_status($status, $type, $messageok, $messagewarn, 
                              $desc = NULL, $updatemsg = NULL)
{
    if($status == 1)
    {
        echo '<h3>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.site_url().
             '/wp-content/plugins/sucuri-scanner/images/ok.png" /> &nbsp; '.
             $messageok.'.</h3>';

        if($updatemsg != NULL){ echo $updatemsg; }
    }
    else
    {
        echo '<h3>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.site_url().
             '/wp-content/plugins/sucuri-scanner/images/warn.png" /> &nbsp; '.
             $messagewarn. '.</h3>';

        if($updatemsg != NULL){ echo $updatemsg; }

        if($type != NULL)
        {
            echo '<form action="" method="post">'.
                 wp_nonce_field('sucuriscan-nonce', 'sucuriscan-harden-action').
                 '<input type="hidden" name="wpscansucuri-doharden" value="wpscansucuri-doharden" />'.
                 '<input type="hidden" name="'.$type.'" '.
                 'value="'.$type.'" />'.
                 '<input class="button-primary" type="submit" name="wpscansucuri-dohardenform" value="Harden it!" />'.
                 '</form><br />';
        }
    }
    if($desc != NULL)
    {
        echo "<i>$desc</i>";
    }

}


function sucuriscan_harden_version()
{
    global $wp_version;
    $cp = 0;
    $updates = get_core_updates();
    if (!is_array($updates))
    {
        $cp = 1;
    }
    else if(empty($updates))
    {
        $cp = 1;
    }
    else if($updates[0]->response == 'latest')
    {
        $cp = 1;
    }
    if(strcmp($wp_version, "3.3") < 0)
    {
        $cp = 0;
    }
    

    sucuriscan_harden_status($cp, NULL, 
                         "WordPress is updated", "WordPress is not updated",
                         NULL);

    if($cp == 0)
    {
        echo "<i>Your current version ($wp_version) is not current. Please update it <a href='update-core.php'>now!</a></i>";
    }
    else
    {
        echo "<i>Your WordPress installation ($wp_version) is current.</i>";
    }
}


function sucuriscan_harden_removegenerator()
{
    /* Enabled by default with this plugin. */
    $cp = 1;
    
    sucuriscan_harden_status($cp, "sucuri_harden_removegenerator", 
                         "WordPress version properly hidden", NULL,
                         "It checks if your WordPress version is being hidden".
                         " from being displayed in the generator tag ".
                         "(enabled by default with this plugin).");
}



function sucuriscan_harden_upload()
{
    $cp = 1;
    $upmsg = NULL;
    if(!is_readable(ABSPATH."/wp-content/uploads/.htaccess"))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file(ABSPATH."/wp-content/uploads/.htaccess");
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if(isset($_POST['sucuriscan_harden_upload']) && isset($_POST['wpscansucuri-doharden']) &&
       $cp == 0)
    {
        if(file_put_contents(ABSPATH."/wp-content/uploads/.htaccess",
                             "\n".
                             "<Files *.php>\ndeny from all\n</Files>")===FALSE)
        {
            $upmsg = sucuriscan_harden_error("ERROR: Unable to create .htaccess file.");
        }
        else
        {
            $upmsg = sucuriscan_harden_ok("Completed. Upload directory successfully secured.");
            $cp = 1;
        }
    }

    sucuriscan_harden_status($cp, "sucuriscan_harden_upload", 
                         "Upload directory properly protected",
                         "Upload directory not protected",
                         "It checks if your upload directory allows PHP ".
                         "execution or if it is browsable.", $upmsg);
}   



function sucuriscan_harden_dbtables()
{
    global $table_prefix;


    if($table_prefix == "wp_")
    {
        $cp = 0;
    }
    else
    {
        $cp = 1;
    }

    sucuriscan_harden_status($cp, "sucuri_harden_dbtables", 
                         "Database table prefix properly modified",
                         "Database table set to the default value. Not recommended",
                         "It checks whether your database table prefix has ".
                         "been changed from the default 'wp_'.");

    if($cp == 0)
    {
        echo '<br /><i>*We do not offer the option to automatically change the table prefix, but it will be available soon on a next release.</i>';
    }
}



function sucuriscan_harden_adminuser()
{
    global $table_prefix;
    global $wpdb;
    $upmsg = NULL;

    $res = $wpdb->get_results("SELECT user_login from ".
                              $table_prefix."users where user_login='admin'");

    $cp = 0;
    if(count($res) == 0)
    {
        $cp = 1;
    }
    if(isset($_POST['sucuriscan_harden_adminuser']) && isset($_POST['wpscansucuri-doharden']) &&
      $cp == 0)
    {
        if(!isset($_POST['sucuriscan_harden_adminusernew']))
        {
            $upmsg = sucuriscan_harden_error("New admin user name not chosen.");
        }
        else
        {
            $_POST['sucuriscan_harden_adminusernew'] = trim($_POST['sucuri_harden_adminusernew']);
            $_POST['sucuriscan_harden_adminusernew'] = htmlspecialchars($_POST['sucuri_harden_adminusernew']);

            if(strlen($_POST['sucuriscan_harden_adminusernew']) < 2)
            {
                $upmsg = sucuriscan_harden_error("New admin user name not chosen.");
            }
            else if(!preg_match('/^[a-zA-Z0-9_-]+$/', 
                    $_POST['sucuriscan_harden_adminusernew'], $regs, 
                    PREG_OFFSET_CAPTURE, 0))
            {
                $upmsg = sucuriscan_harden_error("Invalid user name. Only letters and numbers are allowed.");
            }
            else
            {
                $res = $wpdb->query("UPDATE ".$table_prefix."users ".
                                    "SET user_login = '".
                                    $_POST['sucuriscan_harden_adminusernew']."'".
                                    "WHERE user_login='admin'");
                $cp = 1;
                $upmsg = sucuriscan_harden_ok("User name changed to: ".
                                          $_POST['sucuriscan_harden_adminusernew'].
                                          ". You will be now logged out.");
            }
        }
    }

    sucuriscan_harden_status($cp, NULL, 
                         "Default admin user name (admin) not being used",
                         "Default admin user name (admin) being used. Not recommended",
                         "It checks whether you have the default 'admin' ".
                         "account enabled. Security guidelines recommend ".
                         "creating a new admin user name.", $upmsg);

    if($cp == 0)
    {
        echo '<br />&nbsp;<br />Choose your new admin name (used to login):';
        echo '<form action="" method="post">'.
             wp_nonce_field('sucuriscan-nonce', 'sucuriscan-harden-action').
             '<input type="hidden" name="wpscansucuri-doharden" value="wpscansucuri-doharden" />'.
             '<input type="hidden" name="sucuriscan_harden_adminuser" '.
             'value="sucuriscan_harden_adminuser" />'.
             '<input type="text" name="sucuriscan_harden_adminusernew" value="" />'.
             '<input type="submit" name="wpsucuri-dohardenform" value="Rename the admin user" />'.
             '</form>';
        echo '<b>*Make sure you remember your new admin login name! '.
             'Otherwise you will not be able to login back. You will be logged out after changing it!</b>';
    }
}



function sucuriscan_harden_readme()
{
    $upmsg = NULL;
    $cp = 0;
    if(!is_readable(ABSPATH."/readme.html"))
    {
        $cp = 1;
    }

    if(isset($_POST['sucuriscan_harden_readme']) && 
       isset($_POST['wpscansucuri-doharden']) &&
       $cp == 0)
    {
        if(unlink(ABSPATH."/readme.html") === FALSE)
        {
            $upmsg = sucuriscan_harden_error("Unable to remove readme file.");
        }
        else
        {
            $cp = 1;
            $upmsg = sucuriscan_harden_ok("Readme file removed.");
        }
    }

    sucuriscan_harden_status($cp, "sucuriscan_harden_readme", 
                         "Readme file properly deleted",
                         "Readme file not deleted and leaking the WordPress version",
                         "It checks whether you have the readme.html file ".
                         "available that leaks your WordPress version.", $upmsg);
}



function sucuriscan_harden_phpversion()
{
    $phpv = phpversion();

    if(strncmp($phpv, "5.2", 3) < 0)
    {
        $cp = 0;
    }
    else
    {
        $cp = 1;
    }

    sucuriscan_harden_status($cp, NULL, 
                         "Using an updated version of PHP (v $phpv)",
                         "The version of PHP you are using ($phpv) is not current. Not recommended and not supported",
                         "It checks if you have the latest version of PHP installed.", NULL);
}
?>
