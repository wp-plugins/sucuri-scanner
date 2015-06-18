
<p>
    An API key is required to activate some additional tools available in this
    plugin, the keys are free and you can virtually generate an unlimited number of
    them as long as the domain name and email address are different. The key is used
    to authenticate the HTTP requests sent by the plugin to a public API service
    managed by Sucuri Inc. Do not generate the key if you disagree with this.
    Contact us at <a href="mailto:info@sucuri.net">info@sucuri.net</a> if you
    believe that sensitive data is being sent to us.
</p>

<form action="%%SUCURI.URL.Settings%%" method="post">
    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
    <input type="hidden" name="sucuriscan_plugin_api_key" value="1" />

    <table class="form-table">
        <tbody>
            <tr>
                <td>Domain Name:</td>
                <td><span>%%SUCURI.CleanDomain%%</span></td>
            </tr>

            <tr>
                <td>E-mail Address:</td>
                <td>
                    <select name="sucuriscan_setup_user">
                        %%SUCURI.AdminEmails%%
                    </select>
                </td>
            </tr>
        </tbody>
    </table>

    <button type="submit" class="button button-primary">Proceed</button>
</form>
