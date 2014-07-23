
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-auditlogs">
    <thead>
        <tr>
            <th colspan="2">Audit Logs (%%SUCURI.AuditLogs.Count%% latest logs)</th>
        </tr>
        <tr>
            <th width="150">Date &amp; Time</th>
            <th>Event &amp; Message</th>
        </tr>
    </thead>

    <tbody>
        %%SUCURI.AuditLogs.List%%

        <tr class="sucuriscan-%%SUCURI.AuditLogs.NoItemsVisibility%%">
            <td colspan="2">
                <em>No logs so far.</em>
            </td>
        </tr>

        <tr class="sucuriscan-%%SUCURI.AuditLogs.PaginationVisibility%%">
            <td colspan="2">
                <ul class="sucuriscan-pagination">
                    %%SUCURI.AuditLogs.PaginationLinks%%
                </ul>
            </td>
        </tr>
    </tbody>
</table>
