<?php
/* Sucuri Security - SiteCheck Malware Scanner
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */


if(!defined('SUCURISCAN'))
{
    return(0);
}

/* Sucuri WordPress Integrity page. */

function sucuriscan_core_integrity_function_wrapper($function_name, $stitle, $description){ ?>
    <div class="postbox">
        <h3><?php echo $stitle; ?></h3>
        <div class="inside">
            <form method="post">
                <input type="hidden" name="<?php echo $function_name; ?>nonce" value="<?php echo wp_create_nonce($function_name.'nonce'); ?>" />
                <input type="hidden" name="<?php echo $function_name; ?>" value="1" />
                <p><?php echo $description; ?></p>
                <input class="button-primary" type="submit" name="<?php echo $function_name; ?>" value="Check" />
            </form>
            <br />
            <?php
            if (isset($_POST[$function_name.'nonce']) && isset($_POST[$function_name])) {
                if( function_exists($function_name) ){
                    $function_name();
                }
            }
            ?>
        </div>
    </div>
<?php }

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
                <br />
                <table class="wp-list-table widefat sucuriscan-lastmodified">
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

                        foreach ( $wp_content_hashes as $key => $value) {
                            if ($value['time'] >= $back_days ){
                                $date =  date('d-m-Y H:i:s', $value['time']);
                                printf('<tr><td>%s</td><td>%s</td></tr>', $key, $date);
                            }
                        }
                        ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
<?php }

function sucuriscan_core_integrity_lib() { ?>
    <div class="postbox-container" style="width:75%;">
        <div class="sucuriscan-maincontent">
            <div class="postbox">
               <div class="inside">
                   <h2 align="center">Sucuri WordPress Integrity Checks</h2>
               </div>
            </div>

            <?php
            include_once("lib/core_integrity.php");
            if( isset($_POST['wpsucuri-core-integrity']) ){
                if(!wp_verify_nonce($_POST['sucuriscan_core_integritynonce'], 'sucuriscan_core_integritynonce'))
                {
                    unset($_POST['wpsucuri-core_integrity']);
                }
            }
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
                    'sucuriwp_check_plugins',
                    'Outdated Plugin list',
                    'This test will list any outdated (active) plugins.'
                );

                sucuriscan_core_integrity_function_wrapper(
                    'sucuriwp_check_themes',
                    'Outdated Theme List',
                    'This test will list any outdated theme.'
                );
                ?>
            </div>

            <p align="center">
                <strong>If you have any questions about these tests or this plugin, contact us at <a href="mailto:info@sucuri.net">
                info@sucuri.net</a> or visit <a href="http://sucuri.net">Sucuri Security</a></strong>
            </p>
    <?php
}
