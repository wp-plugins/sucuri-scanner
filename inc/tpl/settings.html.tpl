
%%SUCURI.ModalWhenAPIRegistered%%

<table class="wp-list-table widefat sucuriscan-table sucuriscan-settings">
    <thead>
        <tr>
            <th colspan="3" class="thead-with-button">
                <span>Plugin Settings</span>
                <form action="%%SUCURI.URL.Settings%%" method="post" class="thead-topright-action">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_reset_options" class="button-primary">Reset plugin options</button>
                </form>
            </th>
        </tr>
    </thead>

    <tbody>

        <tr>
            <td colspan="3">
                <p>
                    Most of the tools in this plugin can be used without a specific configuration,
                    but the core features <strong>require an API key</strong> to communicate with
                    the Sucuri services. The key is generated using your administrator e-mail and
                    the domain of this site, this will allow you to have access to our free
                    monitoring tool forever even if you remove the API key and generate it again.
                </p>
            </td>
        </tr>

        <tr class="alternate">
            <td>API Key</td>
            <td>
                <span class="sucuriscan-monospace">%%SUCURI.APIKey%%</span>
            </td>
            <td class="td-with-button">
                <form method="post" class="sucuriscan-%%SUCURI.APIKey.RecoverVisibility%%">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_recover_api_key" class="button-primary">Recover</button>
                </form>

                <form method="post" class="sucuriscan-%%SUCURI.APIKey.ManualKeyFormVisibility%%">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="text" name="sucuriscan_manual_api_key" class="input-text" placeholder="API key sent to your email" />
                    <button type="submit" class="button-primary">Save</button>
                </form>

                <form method="post" class="sucuriscan-%%SUCURI.APIKey.RemoveVisibility%%">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_remove_api_key" class="button-primary button-danger">Remove</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Last Scanning</td>
            <td><span class="sucuriscan-monospace">%%SUCURI.ScanningRuntimeHuman%%</span></td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Home%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_force_scan" class="button-primary">Force Scan</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>Scanning frequency</td>
            <td><span class="sucuriscan-monospace">%%SUCURI.ScanningFrequency%%</span></td>
            <td class="td-with-button">
                <form method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_scan_frequency">
                        %%SUCURI.ScanningFrequencyOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr class="sucuriscan-%%SUCURI.ScanningInterfaceVisibility%%">
            <td>Scanning interface</td>
            <td><span class="sucuriscan-monospace">%%SUCURI.ScanningInterface%%</span></td>
            <td class="td-with-button">
                <form method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_scan_interface">
                        %%SUCURI.ScanningInterfaceOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

    </tbody>
</table>


<form method="post">
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

            <tr>
                <td colspan="3">
                    <div>
                        <label>
                            <span>Send notifications to this e-mail:</span>
                            <input type="text" name="sucuriscan_notify_to" value="%%SUCURI.NotificationEmail%%" />
                        </label>
                    </div>
                </td>
            </tr>

            %%SUCURI.NotificationOptions%%

        </tbody>
    </table>
</form>
