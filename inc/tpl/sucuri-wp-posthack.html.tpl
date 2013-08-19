<div class="wrap">
    <h2 id="warnings_hook"></h2>
    <div class="sucuriscan_header"><img src="%%SUCURI.SucuriURL%%/inc/images/logo.png">
        <h2>Sucuri Security WordPress Plugin</h2>
    </div>

    <div class="postbox-container" style="width:75%;">
        <div class="sucuriscan-maincontent">
            <div class="postbox">
               <div class="inside">
                   <h2 align="center">Sucuri Plugin Post-Hack</h2>
               </div>
            </div>

            <div id="poststuff">
                <div class="postbox">
                    <h3>Post-Hack - Update WP-Config Keys</h3>
                    <div class="inside">
                        <form method="post">
                            <input type="hidden" name="sucuri_posthack_nonce" value="%%SUCURI.PosthackNonce%%" />
                            <input type="hidden" name="sucuri_posthack_action" value="update_wpconfig" />

                            <p>
                                Use this button to update the security keys stored in the <code>wp-config.php</code>
                                file, we will use the official Wordpress Secret-Key API Generator. After the
                                update your current session will be closed and you'll need to login again.
                            </p>

                            <p>
                                <input type="hidden" name="sucuri_update_wpconfig" value="0" />
                                <input type="checkbox" name="sucuri_update_wpconfig" value="1" />
                                <label for="sucuri_update_wpconfig">I understand that this operation can not be reverted.</label>
                            </p>

                            <input type="submit" value="Update WP-Config Keys" class="button button-primary" />
                        </form>

                        <div style="%%SUCURI.WPConfigUpdate.Display%%" class="sucuri_update_wpconfig_process">
                            <textarea>%%SUCURI.WPConfigUpdate.NewConfig%%</textarea>
                        </div>
                    </div>
                </div>

                <div class="postbox">
                    <h3>Post-Hack - Reset user password</h3>
                    <div class="inside">
                        <form method="post">
                            <input type="hidden" name="sucuri_posthack_nonce" value="%%SUCURI.PosthackNonce%%" />
                            <input type="hidden" name="sucuri_posthack_action" value="reset_password" />

                            <p>
                                Use this button to reset the current password for some specific users or for all
                                of them. We will send an email to each of those users adivising the password change
                                that includes the new password automatically generated by Wordpress. After the
                                password reset your current session will be closed and you'll need to login again.
                            </p>

                            <table class="wp-list-table widefat">
                                <thead>
                                    <tr>
                                        <th class="manage-column column-cb check-column">
                                            <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                                            <input id="cb-select-all-1" type="checkbox">
                                        </th>
                                        <th class="manage-column column-name">Username</th>
                                        <th class="manage-column column-description">Display name</th>
                                        <th class="manage-column column-description">Email address</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    %%SUCURI.ResetPassword.UserList%%
                                </tbody>
                            </table>

                            <p>
                                <input type="hidden" name="sucuri_reset_password" value="0" />
                                <input type="checkbox" name="sucuri_reset_password" value="1" />
                                <label for="sucuri_reset_password">I understand that this operation can not be reverted.</label>
                            </p>

                            <input type="submit" value="Reset User Password" class="button button-primary" />
                        </form>
                    </div>
                </div>
            </div><!-- End poststuff -->

        </div><!-- End sucuriscan-maincontent -->
    </div><!-- End postbox-container -->

    %%SUCURI.SucuriWPSidebar%%

</div><!-- End wrap -->
