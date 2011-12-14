<?php
/*
Plugin Name: Sucuri Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: This plugin allows you to scan your website using the Sucuri SiteCheck Malware Scanner on your WordPress site. It will check for malware, spam, blacklisting and other security issues (htaccess redirections, hidden code, etc). Yes, it is free. Similar to the scans provided online at http://sitecheck.sucuri.net
Author: http://sucuri.net
Version: 1.1.6
Author URI: http://sucuri.net
*/


/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

define('SUCURISCAN','sucuriscan');
define('SUCURISCAN_VERSION','1.1.6');
define( 'SUCURI_URL',plugin_dir_url( __FILE__ ));
define( 'SUCURI_IMG',SUCURI_URL.'images/');



/* Starting Sucuri Scan side bar. */
function sucuriscan_menu() 
{
    add_menu_page('Sucuri Scanner', 'Sucuri Scanner', 'manage_options', 
                  'sucuriscan', 'sucuri_scan_page', SUCURI_IMG.'menu-icon.png');
    add_submenu_page('sucuriscan', 'Sucuri Scanner', 'Sucuri Scanner', 'manage_options',
                     'sucuriscan', 'sucuri_scan_page');

    add_submenu_page('sucuriscan', '1-click Hardening', '1-click Hardening', 'manage_options',
                     'sucuriscan_hardening', 'sucuriscan_hardening_page');

    add_submenu_page('sucuriscan', 'Malware removal', 'Malware removal', 'manage_options',
                     'sucuriscan_removal', 'sucuri_removal_page');
}



function sucuri_removal_page()
{
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }


    /* Hardening page. */
    echo '<div class="wrap">';
    echo '<h2>Sucuri Malware Removal</h2>';

    echo '<h3>Get your site 100% clean and malware/blacklist free.</h3>'; 

    echo "<hr />";

    echo "<p>If our scanner is identifying any security problems on your site, we can get that
    cleaned for you. Just sign up with us here: <a href='http://sucuri.net/signup'>http://sucuri.net/signup</a> and our team will take care of it for you.</p>";
    echo "<hr />";
    echo "<h3>Get your site cleaned in under 4 hours (3 simple steps)</h3>";
    echo "<ol>";
    echo "<li>Sign up here: <a href='http://sucuri.net/signup'>http://sucuri.net/signup</a></li>";
    echo "<li>Click on malware removal request (inside the support page)</li>";
    echo "<li>Done! Go grab a coffee and wait for us to get it done</li>";
    echo "</ol>";
    ?>
    <br /><br />
    <b>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></b>
   <br />

    </div>
    <?php
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
    echo '<h2>Sucuri SiteCheck Malware Scanner</h2>';
  

    echo '<h3>Scan your site for malware using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a> right in your WordPress dashboard. The Sucuri SiteCheck scans will let you know if your site is compromised with malware, blackhat spam, website defacement, or if you are blacklisted.</h3>'; 
    ?>

    <form action="" method="post">
    <input type="hidden" name="wpsucuri-doscan" value="wpsucuri-doscan" />
    <input class="button-primary" type="submit" name="wpsucuri_doscanrun" value="Scan this site now!" />
    </form>

    <br /><br />
    <strong>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">sucuri.net</a></strong>
   <br />
    </div>

    <?php
}



function sucuriscan_print_scan()
{
    $myresults = wp_remote_get("http://sitecheck.sucuri.net/scanner/?serialized&fromwp&scan=".home_url(), array("timeout" => 180));

    if(is_wp_error($myresults))
    {
        print_r($myresults);
        return;
    }


    $res = unserialize($myresults['body']);

    echo '<div class="wrap">';
    echo '<h2>Sucuri SiteCheck Malware Scanner</h2>';

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
    echo '<i>More details here <a href="http://sitecheck.sucuri.net/scanner/?&scan='.home_url().'">http://sitecheck.sucuri.net/scanner/?&scan='.home_url().'</a></i>';


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

    foreach($res['BLACKLIST']['INFO'] as $blres)
    {
        echo "<b>CLEAN: </b>".htmlspecialchars($blres[0])." <a href=''>".htmlspecialchars($blres[1])."</a><br />";
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
    if(strcmp($wp_version, "3.3") >= 0)
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

    ?>
    <br /><br />
    <b>If you have any questions about these scan results, or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></b>
    <br />
    </div>
    <?php
}


/* Sucuri one-click hardening page. */
function sucuriscan_hardening_page()
{
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }
    include_once("sucuriscan_hardening.php");



    /* Hardening page. */
    echo '<div class="wrap">';
    echo '<h2>Sucuri 1-Click WordPress Hardening</h2>';

    echo '<h3>Secure your WordPress with a one-click hardening.</h3>'; 

    echo "<hr />";
    sucuriscan_harden_version();
    echo "<hr />";
    sucuriscan_harden_removegenerator();
    echo "<hr />";
    sucuriscan_harden_upload();
    echo "<hr />";
    sucuriscan_harden_dbtables();
    echo "<hr />";
    sucuriscan_harden_adminuser();
    echo "<hr />";
    sucuriscan_harden_readme();
    echo "<hr />";
    sucuriscan_harden_phpversion();
    echo "<hr />";
    ?>
    <br /><br />
    <b>If you have any question about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></b>
   <br />

    </div>
    <?php
}




/* Sucuri's admin menu. */
add_action('admin_menu', 'sucuriscan_menu');
remove_action('wp_head', 'wp_generator');


?>
