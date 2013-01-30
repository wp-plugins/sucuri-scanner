<?php
/*
Plugin Name: Sucuri Security - SiteCheck Malware Scanner
Plugin URI: http://sitecheck.sucuri.net/
Description: The <a href="http://sucuri.net">Sucuri Security</a> - SiteCheck Malware Scanner plugin enables you to <strong>scan your WordPress site using <a href="http://sitecheck.sucuri.net">Sucuri SiteCheck</a></strong> right in your WordPress dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.

You can also scan your site at <a href="http://sitecheck.sucuri.net">SiteCheck.Sucuri.net</a>.

Author: Sucuri Security
Version: 1.2.1
Author URI: http://sucuri.net
*/

/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

define('SUCURISCAN','sucuriscan');
define('SUCURISCAN_VERSION','1.1.7');
define( 'SUCURI_URL',plugin_dir_url( __FILE__ ));

/* Requires files. */
//require_once(dirname(__FILE__ ) . '/inc/scripts.php');
add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );
function sucuriscan_admin_script_style_registration() {

echo '<link rel="stylesheet" href="'.SUCURI_URL.'/inc/css/sucuriscan-default-css.css" type="text/css" media="all" />';

}

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
                    <input class="button-primary" type="submit" name="wpsucuri_doscanrun" value="Scan this site now!" />
                </form>
                
                <p><strong>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">sucuri.net</a></strong></p>

            </div><!-- End sucuriscan-maincontent -->    
        </div><!-- End postbox-container -->        
    
    <?php include_once("lib/sidebar.php");  ?>     

    </div><!-- End Wrap -->

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
                <p>If you have any questions about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></p>

            </div><!-- End sucuriscan-maincontent -->    
        </div><!-- End postbox-container -->       
    
    <?php include_once("lib/sidebar.php");  ?>     

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
    
    <?php include_once("lib/sidebar.php");  ?>     

    </div><!-- End Wrap -->

    <?php
}

/* Sucuri's admin menu. */

add_action('admin_menu', 'sucuriscan_menu');
remove_action('wp_head', 'wp_generator');

?>