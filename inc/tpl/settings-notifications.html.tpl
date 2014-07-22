
<form action="%%SUCURI.URL.Settings%%#settings-notifications" method="post">
    <table class="wp-list-table widefat sucuriscan-table sucuriscan-settings-notifications">
        <thead>
            <tr>
                <th colspan="3" class="thead-with-button">
                    <span>Email Alerts Settings</span>
                    <div class="thead-topright-action">
                        <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                        <button type="submit" name="sucuriscan_save_notification_settings" class="button-primary">Save</button>
                    </div>
                </th>
            </tr>
        </thead>

        <tbody>

            %%SUCURI.NotificationOptions%%

        </tbody>
    </table>
</form>
