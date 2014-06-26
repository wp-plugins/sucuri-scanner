
<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-auditlogs">
    <thead>
        <tr>
            <th colspan="2" class="thead-with-button">
                <span>Audit Logs (%%SUCURI.AuditLogs.Count%% logs)</span>
                <form action="%%SUCURI.URL.Settings%%" method="post" class="thead-topright-action">
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

        <tr class="sucuriscan-%%SUCURI.AuditLogs.MaxItemsVisibility%%">
            <td colspan="2">
                <div class="sucuriscan-maxper-page">
                    Showing <b>%%SUCURI.AuditLogs.MaxPerPage%%</b> out of <b>%%SUCURI.AuditLogs.Count%%</b>
                    &nbsp;-&nbsp;
                    <a href="%%SUCURI.URL.Core_integrity%%&show_all=1">Show all</a>
                </div>
            </td>
        </tr>

        <tr class="sucuriscan-%%SUCURI.AuditLogs.NoItemsVisibility%%">
            <td colspan="2">
                <em>No logs so far.</em>
            </td>
        </tr>
    </tbody>
</table>
