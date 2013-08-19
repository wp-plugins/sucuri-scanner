<tr>
    <th class="check-column">
        <input type="checkbox" name="user_ids[]" value="%%SUCURI.AdminUsers.UserId%%" />
    </th>
    <td>%%SUCURI.AdminUsers.Username%%</td>
    <td><a href="mailto:%%SUCURI.AdminUsers.Email%%">%%SUCURI.AdminUsers.Email%%</a></td>
    <td class="adminusers-lastlogin">
        <table>
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
</tr>
