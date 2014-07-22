
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-auditlogs">
    <thead>
        <tr>
            <th colspan="2" class="thead-with-button">
                <span>Audit Logs (%%SUCURI.AuditLogs.Count%% logs)</span>
                <form action="%%SUCURI.URL.Home%%" method="post" class="thead-topright-action">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_force_scan" class="button-primary">Force Scan</button>
                </form>
            </th>
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
