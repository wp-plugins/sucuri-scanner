
<div id="poststuff" class="sucuriscan-reset-users-password">
    <div class="postbox">
        <div class="inside">
            <form method="post">
                <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                <input type="hidden" name="sucuriscan_reset_password" value="1" />

                <p>
                    Use this button to reset the current password for some specific users or for all
                    of them. We will send an email to each of those users adivising the password change
                    that includes the new password automatically generated by WordPress. After the
                    password reset your current session will be closed and you'll need to login again.
                </p>

                <table class="wp-list-table widefat sucuriscan-table">
                    <thead>
                        <tr>
                            <th class="manage-column column-cb check-column">
                                <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                                <input id="cb-select-all-1" type="checkbox">
                            </th>
                            <th class="manage-column">User</th>
                            <th class="manage-column">Email address</th>
                            <th class="manage-column">Registered</th>
                            <th class="manage-column">Roles</th>
                        </tr>
                    </thead>

                    <tbody>
                        %%SUCURI.ResetPassword.UserList%%
                    </tbody>
                </table>

                <p>
                    <label>
                        <input type="hidden" name="sucuriscan_process_form" value="0" />
                        <input type="checkbox" name="sucuriscan_process_form" value="1" />
                        <span>I understand that this operation can not be reverted.</span>
                    </label>
                </p>

                <input type="submit" value="Reset User Password" class="button button-primary" />
            </form>
        </div>
    </div>
</div>
