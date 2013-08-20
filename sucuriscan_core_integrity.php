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

function sucuriscan_core_integrity_function_wrapper($function_name, $description)
{
    echo '<div class="postbox">';
        echo '<div class="inside">';
        echo '<form action="" method="post">'.
                '<input type="hidden" name="'.$function_name.'nonce" value="'.wp_create_nonce($function_name.'nonce').'" />'.
                '<input type="hidden" name="'.$function_name.'" value="'.$function_name.'" />'.

                '<p>'.$description.'</p>'.
                '<input class="button-primary" type="submit" name="'.$function_name.'" value="Check">'.
            '</form>';
        echo '</div>';
    echo '</div>';

    if (isset($_POST[$function_name.'nonce']) && isset($_POST[$function_name])) {
        $function_name();
    }
}

function sucuriscan_core_integrity_wp_content_wrapper()
{
    echo '<div class="postbox">';
        echo '<div class="inside">';
        echo '<form action="" method="post">'.
                '<input type="hidden" name="sucuriwp_content_checknonce" value="'.wp_create_nonce('sucuriwp_content_checknonce').'" />'.
                '<input type="hidden" name="sucuriwp_content_check" value="sucuriwp_content_check" />'.

                '<p>This test will list all files inside wp-content that have been modified in the past

                <select name="sucuriwp_content_check_back">
                  <option value="1">1</option>
                  <option value="3">3</option>
                  <option value="7">7</option>
                  <option value="30">30</option>
                </select> days. (select the number of days first)</p>'.

                '<input class="button-primary" type="submit" name="sucuriwp_content_check" value="Check">'.
            '</form>';
        echo '</div>';
    echo '</div>';

    if (isset($_POST['sucuriwp_content_checknonce']) && isset($_POST['sucuriwp_content_check'])) {
        sucuriwp_content_check();
    }
}

function sucuriscan_core_integrity_lib()
{
        echo '<h2 id="warnings_hook"></h2>';
        echo '<div class="postbox-container" style="width:75%;">';
            echo '<div class="sucuriscan-maincontent">';

                echo '<div class="postbox">';
                   echo '<div class="inside">';
                       echo '<h2 align="center">Sucuri WordPress Integrity Checks</h2>';
                   echo '</div>';
                echo '</div>';

    include_once("lib/core_integrity.php");

    if(isset($_POST['wpsucuri-core-integrity']))
    {
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
                    'This test will check wp-includes, wp-admin, and the top directory files against the latest WordPress hashing database. If any of those files were modified, it is a big sign of a possible compromise.'
                    );

                sucuriscan_core_integrity_wp_content_wrapper();

                sucuriscan_core_integrity_function_wrapper(
                    'sucuriwp_list_admins', 
                    'List all administrator users and their latest login time.'
                    );
                sucuriscan_core_integrity_function_wrapper(
                    'sucuriwp_check_plugins', 
                    'This test will list any outdated (active) plugins.'
                    );
                sucuriscan_core_integrity_function_wrapper(
                    'sucuriwp_check_themes', 
                    'This test will list any outdated theme.'
                    );
            ?>

        </div>

        <p align="center"><strong>If you have any questions about these tests or this plugin, contact us at info@sucuri.net or visit <a href="http://sucuri.net">Sucuri Security</a></strong></p>

    <?php
}
