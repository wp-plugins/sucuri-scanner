
<div id="poststuff" class="sucuriscan-update-secret-keys">
    <div class="postbox">
        <div class="inside">
            <form method="post">
                <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                <input type="hidden" name="sucuriscan_update_wpconfig" value="1" />

                <p>
                    Use this button to update the security keys stored in the <code>wp-config.php</code>
                    file, we will use the official WordPress Secret-Key API Generator. After the
                    update your current session will be closed and you'll need to login again.
                </p>

                <p>
                    <label>
                        <input type="hidden" name="sucuriscan_process_form" value="0" />
                        <input type="checkbox" name="sucuriscan_process_form" value="1" />
                        <span>I understand that this operation can not be reverted.</span>
                    </label>
                </p>

                <input type="submit" value="Update WP-Config Keys" class="button button-primary" />
            </form>

            <div class="sucuriscan_wpconfig_keys_updated sucuriscan-%%SUCURI.WPConfigUpdate.Visibility%%">
                <textarea>%%SUCURI.WPConfigUpdate.NewConfig%%</textarea>
            </div>
        </div>
    </div>
</div>
