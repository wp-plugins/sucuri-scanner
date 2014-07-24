
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-last-logins">
    <thead>
        <tr>
            <th colspan="6" class="thead-with-button">
                <span>User last logins</span>
                <span class="thead-topright-action sucuriscan-lastlogin-outof">
                    %%SUCURI.UserList.Limit%% per page out of %%SUCURI.UserList.Total%%
                </span>
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

        <tr class="sucuriscan-%%SUCURI.UserList.NoItemsVisibility%%">
            <td colspan="6">
                <em>No logs so far.</em>
            </td>
        </tr>

        <tr class="sucuriscan-%%SUCURI.UserList.PaginationVisibility%%">
            <td colspan="6">
                <ul class="sucuriscan-pagination">
                    %%SUCURI.UserList.Pagination%%
                </ul>
            </td>
        </tr>
    </tbody>
</table>
