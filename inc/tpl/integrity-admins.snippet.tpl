<tr>
    <td>%%SUCURI.AdminUsers.Username%%</td>
    <td><a href="mailto:%%SUCURI.AdminUsers.Email%%">%%SUCURI.AdminUsers.Email%%</a></td>
    <td class="adminusers-lastlogin">
        <div class="sucuri-%%SUCURI.AdminUsers.NoLastLogins%%">
            <i>There isn't information available for this account.</i>
        </div>

        <table class="widefat sucuri-%%SUCURI.AdminUsers.NoLastLoginsTable%%">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Date & Time</th>
                </tr>
            </thead>
            <tbody>
                %%SUCURI.AdminUsers.LastLogins%%
            </tbody>
        </table>
    </td>
    <td>
        <a href="%%SUCURI.AdminUsers.UserURL%%" target="_blank" class="button-primary">Edit</a>
    </td>
</tr>
