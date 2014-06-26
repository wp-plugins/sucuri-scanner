
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-last-logins">
    <thead>
        <tr>
            <th colspan="6" class="thead-with-button">
                <span>User logins (latest %%SUCURI.UserListLimit%%, newest to oldest)</span>
                <a href="%%SUCURI.CurrentURL%%&limit=0" class="button button-primary lastlogins-showall thead-topright-action sucuri-%%SUCURI.UserList.ShowAll%%">Show all results</a>
            </th>
        </tr>
        <tr>
            <th class="manage-column">No.</th>
            <th class="manage-column">User</th>
            <th class="manage-column">IP Address</th>
            <th class="manage-column">Hostname</th>
            <th class="manage-column">Date/Time</th>
            <th class="manage-column">&nbsp;</th>
        </tr>
    </thead>

    <tbody>
        %%SUCURI.UserList%%
    </tbody>
</table>
