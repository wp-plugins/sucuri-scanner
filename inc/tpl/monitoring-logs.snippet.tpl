
<tr class="%%SUCURI.AuditLog.CssClass%%">
    <td>%%SUCURI.AuditLog.SucuriBlockReason%%</td>
    <td>
        <span class="sucuriscan-monospace" title="%%SUCURI.AuditLog.RequestDate%% %%SUCURI.AuditLog.RequestTime%% %%SUCURI.AuditLog.RequestTimezone%%">
            %%SUCURI.AuditLog.RequestTime%% %%SUCURI.AuditLog.RequestTimezone%%
        </span>
    </td>
    <td><span class="sucuriscan-monospace">%%SUCURI.AuditLog.RemoteAddr%%</span></td>
    <td>
        <div class="sucuriscan-wraptext">
            <a href="#TB_inline?width=600&height=300&inlineId=sucuriscan-reqsummary-%%SUCURI.AuditLog.Id%%" title="Access Log Summary" class="thickbox">
                <span class="sucuriscan-monospace">%%SUCURI.AuditLog.ResourcePath%%</span>
            </a>
        </div>

        <div id="sucuriscan-reqsummary-%%SUCURI.AuditLog.Id%%" style="display:none">
            <div class="sucuriscan-request-summary">
                <ul class="sucuriscan-list-as-table">
                    <li>
                        <label>Blocked Reason:</label>
                        <span>%%SUCURI.AuditLog.SucuriBlockReason%%</span>
                    </li>
                    <li>
                        <label>Remote Address:</label>
                        <span>%%SUCURI.AuditLog.RemoteAddr%%</span>
                    </li>
                    <li>
                        <label>Date/Time (Timezone)</label>
                        <span>%%SUCURI.AuditLog.RequestDate%% %%SUCURI.AuditLog.RequestTime%% (%%SUCURI.AuditLog.RequestTimezone%%)</span>
                    </li>
                    <li>
                        <label>Resource Path:</label>
                        <span>%%SUCURI.AuditLog.ResourcePath%%</span>
                    </li>
                    <li>
                        <label>Request Method:</label>
                        <span>%%SUCURI.AuditLog.RequestMethod%%</span>
                    </li>
                    <li>
                        <label>HTTP Protocol:</label>
                        <span>%%SUCURI.AuditLog.HttpProtocol%%</span>
                    </li>
                    <li>
                        <label>HTTP Status:</label>
                        <span>%%SUCURI.AuditLog.HttpStatus%% %%SUCURI.AuditLog.HttpStatusTitle%%</span>
                    </li>
                    <li>
                        <label>HTTP Bytes Sent:</label>
                        <span>%%SUCURI.AuditLog.HttpBytesSent%%</span>
                    </li>
                    <li>
                        <label>HTTP Referer:</label>
                        <span>%%SUCURI.AuditLog.HttpReferer%%</span>
                    </li>
                    <li>
                        <label>HTTP User Agent:</label>
                        <span>%%SUCURI.AuditLog.HttpUserAgent%%</span>
                    </li>
                </ul>
            </div>
        </div>
    </td>
</tr>
