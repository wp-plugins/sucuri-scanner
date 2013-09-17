<div class="wrap">
    <h2 id="warnings_hook"></h2>
    <div class="sucuriscan_header"><img src="%%SUCURI.SucuriURL%%/inc/images/logo.png">
        <h2>Sucuri Security WordPress Plugin</h2>
    </div>

    <div class="postbox-container" style="width:75%;">
        <div class="sucuriscan-maincontent">
            <div class="postbox">
               <div class="inside">
                   <h2 align="center">Sucuri Plugin Last-Logins</h2>
               </div>
            </div>

            <div id="poststuff" class="sucuri-%%SUCURI.LastLoginsSettings.Display%%">
                <div class="postbox">
                    <h3>User logins settings</h3>
                    <div class="inside">
                        <form method="POST">
                            <input type="hidden" name="sucuri_lastlogins_nonce" value="%%SUCURI.LastLoginsNonce%%" />

                            <p>As part of the administrator accounts, you can choose who can see alerts of Last-Logins in the Wordpress Dashboard.</p>
                            <label>
                                <input type="radio" name="lastlogin_alerts" value="enable_everyone" %%SUCURI.LastLoginsAlerts.EnableEveryone%% />
                                Enable last logins warnings for everyone.
                            </label>
                            <br />
                            <label>
                                <input type="radio" name="lastlogin_alerts" value="disable_everyone" %%SUCURI.LastLoginsAlerts.DisableEveryone%% />
                                Disable last login flashs for everyone.
                            </label>
                            <br />
                            <label>
                                <input type="radio" name="lastlogin_alerts" value="just_admins" %%SUCURI.LastLoginsAlerts.JustAdmins%% />
                                Disable last logins for any non admins.
                            </label>
                            <p>
                                <input type="submit" value="Save values"  class="button-primary" />
                                <label class="sucuri-inline-error sucuri-%%SUCURI.LastLogins.DatastoreWritable%%">The Last-Logins datastore file is not writable, future logins won't be stored.</label>
                            </p>
                        </form>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <table class="wp-list-table widefat">
                <thead>
                    <tr>
                        <th colspan="4">
                            User logins (latest 10, newest to oldest)
                            <a href="%%SUCURI.CurrentURL%%&limit=0" class="button button-primary lastlogins-showall sucuri-%%SUCURI.UserList.ShowAll%%">Show all results</a>
                        </th>
                    </tr>
                    <tr>
                        <th class="manage-column">Username</th>
                        <th class="manage-column">Email</th>
                        <th class="manage-column">IP Address</th>
                        <th class="manage-column">Date/Time</th>
                    </tr>
                </thead>

                <tbody>
                    %%SUCURI.UserList%%
                </tbody>
            </table>

        </div><!-- End sucuriscan-maincontent -->
    </div><!-- End postbox-container -->

    %%SUCURI.SucuriWPSidebar%%

</div><!-- End wrap -->
