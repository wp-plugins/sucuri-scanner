
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-auditlogs">
    <thead>
        <tr>
            <th colspan="4">Audit Logs (%%SUCURI.AuditLogs.Count%% latest logs)</th>
        </tr>
        <tr>
            <th>&nbsp;</th>
            <th>Username</th>
            <th>IP Address</th>
            <th>Event Message</th>
        </tr>
    </thead>

    <tbody>
        %%SUCURI.AuditLogs.List%%

        <tr class="sucuriscan-%%SUCURI.AuditLogs.NoItemsVisibility%%">
            <td colspan="4">
                <em>No logs so far.</em>
            </td>
        </tr>

        <tr class="sucuriscan-%%SUCURI.AuditLogs.PaginationVisibility%%">
            <td colspan="4">
                <ul class="sucuriscan-pagination">
                    %%SUCURI.AuditLogs.PaginationLinks%%
                </ul>
            </td>
        </tr>
    </tbody>
</table>
