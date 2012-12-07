<?php
/* Sucuri Security - SiteCheck Malware Scanner
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */
if(!defined('SUCURISCAN'))
{
    return(0);
}

function sucuriscan_wrapper_open($msg)
{
    ?>
    <div class="postbox">
        <h3><?php echo $msg; ?></h3>
        <div class="inside">
    <?php
}
function sucuriscan_wrapper_close()
{
    ?>
    </div>
    </div>
    <?php
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
    if($desc != NULL)
    {
        echo "<p>$desc</p>";
    }

    if($status == 1)
    {
        echo '<h4>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.SUCURI_URL.'images/ok.png" /> &nbsp; '.
             $messageok.'.</h4>';

        if($updatemsg != NULL){ echo $updatemsg; }
    }
    else
    {
        echo '<h4>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.SUCURI_URL.'images/warn.png" /> &nbsp; '.
             $messagewarn. '.</h4>';

        if($updatemsg != NULL){ echo $updatemsg; }

        if($type != NULL)
        {
            echo '<input class="button-primary" type="submit" name="'.$type.'" 
                         value="Harden it!" />';
        }
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
    if(strcmp($wp_version, "3.4.2") < 0)
    {
        $cp = 0;
    }
    $wp_version = htmlspecialchars($wp_version);


    sucuriscan_wrapper_open("Verify WordPress Version");


    sucuriscan_harden_status($cp, NULL, 
                         "WordPress is updated", "WordPress is not updated",
                         NULL);

    if($cp == 0)
    {
        echo "<p>Your current version ($wp_version) is not current.</p><p><a class='button-primary' href='update-core.php'>Update now!</a></p>";
    }
    else
    {
        echo "<p>Your WordPress installation ($wp_version) is current.</p>";
    }
    sucuriscan_wrapper_close();
}

function sucuri_harden_removegenerator()
{
    /* Enabled by default with this plugin. */
    $cp = 1;
    
    sucuriscan_wrapper_open("Remove WordPress Version");

    sucuriscan_harden_status($cp, "sucuri_harden_removegenerator", 
                         "WordPress version properly hidden", NULL,
                         "It checks if your WordPress version is being hidden".
                         " from being displayed in the generator tag ".
                         "(enabled by default with this plugin).");

    sucuriscan_wrapper_close();
}

function sucuriscan_harden_upload()
{
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

    if(isset($_POST['sucuriscan_harden_upload']) &&
       isset($_POST['wpsucuri-doharden']) &&
       $cp == 0)
    {
        if(file_put_contents("$htaccess_upload",
                             "\n<Files *.php>\ndeny from all\n</Files>")===FALSE)
        {
            $upmsg = sucuriscan_harden_error("ERROR: Unable to create .htaccess file.");
        }
        else
        {
            $upmsg = sucuriscan_harden_ok("COMPLETE: Upload directory successfully hardened");
            $cp = 1;
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

function sucuriscan_harden_wpcontent()
{
    $cp = 1;
    $upmsg = NULL;
    $htaccess_content = ABSPATH."/wp-content/.htaccess";

    if(!is_readable($htaccess_content))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file($htaccess_content);
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if(isset($_POST['sucuriscan_harden_wpcontent']) &&
       isset($_POST['wpsucuri-doharden']) &&
       $cp == 0)
    {
        if(file_put_contents("$htaccess_content",
                             "\n<Files *.php>\ndeny from all\n</Files>")===FALSE)
        {
            $upmsg = sucuriscan_harden_error("ERROR: Unable to create .htaccess file.");
        }
        else
        {
            $upmsg = sucuriscan_harden_ok("COMPLETE: wp-content directory successfully hardened");
            $cp = 1;
        }
    }

    sucuriscan_wrapper_open("Restrict wp-content Access");
    sucuriscan_harden_status($cp, "sucuriscan_harden_wpcontent", 
                         "WP-content directory properly hardened",
                         "WP-content directory not hardened",
                         "This option blocks direct PHP access to any file inside wp-content. <p><strong>WARN: <span class='error-message'>Do not enable this option if ".
                         "your site uses TimThumb or similar scripts.</span> If you enable and you need to disable, please remove the .htaccess from wp-content.</strong></p>", $upmsg);
    sucuriscan_wrapper_close();
}   

function sucuriscan_harden_wpincludes()
{
    $cp = 1;
    $upmsg = NULL;
    $htaccess_content = ABSPATH."/wp-includes/.htaccess";

    if(!is_readable($htaccess_content))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file($htaccess_content);
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if(isset($_POST['sucuriscan_harden_wpincludes']) &&
       isset($_POST['wpsucuri-doharden']) &&
       $cp == 0)
    {
        if(file_put_contents("$htaccess_content",
                             "\n<Files *.php>\ndeny from all\n</Files>\n<Files wp-tinymce.php>\nallow from all\n</Files>\n")===FALSE)
        {
            $upmsg = sucuriscan_harden_error("ERROR: Unable to create .htaccess file.");
        }
        else
        {
            $upmsg = sucuriscan_harden_ok("COMPLETE: wp-includes directory successfully hardened.");
            $cp = 1;
        }
    }

    sucuriscan_wrapper_open("Restrict wp-includes Access");
    sucuriscan_harden_status($cp, "sucuriscan_harden_wpincludes", 
                         "wp-includes directory properly hardened",
                         "wp-includes directory not hardened",
                         "This option blocks direct PHP access to any file inside wp-includes. ", $upmsg);
    sucuriscan_wrapper_close();
}   

function sucuriscan_harden_phpversion()
{
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
