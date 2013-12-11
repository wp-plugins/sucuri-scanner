<div class="wrap">
    <h2 id="warnings_hook"></h2>
    <div class="sucuriscan_header">
        <a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security">
            <img src="%%SUCURI.SucuriURL%%/inc/images/logo.png" alt="Sucuri Security" />
        </a>
        <h2>Sucuri Security WordPress Plugin</h2>
    </div>

    <div class="postbox-container" style="width:75%;">
        <div class="sucuriscan-maincontent">
            <div class="postbox">
               <div class="inside">
                   <h2 align="center">Sucuri Plugin Last-Logins</h2>
               </div>
            </div>

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
