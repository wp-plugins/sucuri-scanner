
<div id="poststuff" class="sucuriscan-general-settings">
    %%SUCURI.SettingsSection.ApiKey%%

    %%SUCURI.SettingsSection.DataStorage%%

    %%SUCURI.SettingsSection.ApiProxy%%

    %%SUCURI.SettingsSection.ApiSSL%%

    %%SUCURI.SettingsSection.ApiTimeout%%

    %%SUCURI.SettingsSection.ReverseProxy%%

    %%SUCURI.SettingsSection.PasswordCollector%%

    %%SUCURI.SettingsSection.IPDiscoverer%%

    %%SUCURI.SettingsSection.CommentMonitor%%

    %%SUCURI.SettingsSection.XhrMonitor%%

    %%SUCURI.SettingsSection.ResetOptions%%
</div>

<table class="wp-list-table widefat sucuriscan-table sucuriscan-striped-table sucuriscan-settings">
    <tbody>
        <tr>
            <td>Test email alerts</td>
            <td><em>(Test ability to send email alerts)</em></td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_debug_email" value="1" />
                    <button type="submit" class="button-primary">Proceed</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Send plugin alerts to</td>
            <td>%%SUCURI.NotifyTo%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="text" name="sucuriscan_notify_to" class="input-text" placeholder="Separated by commas" />
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Maximum alerts per hour</td>
            <td>%%SUCURI.EmailsPerHour%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_emails_per_hour">
                        %%SUCURI.EmailsPerHourOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Consider brute-force after</td>
            <td>%%SUCURI.MaximumFailedLogins%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_maximum_failed_logins">
                        %%SUCURI.MaximumFailedLoginsOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Display audit report</td>
            <td>%%SUCURI.AuditReportStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_audit_report" value="%%SUCURI.AuditReportSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.AuditReportSwitchCssClass%%">%%SUCURI.AuditReportSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Audit report limit</td>
            <td>Process latest %%SUCURI.AuditReportLimit%% logs</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="text" name="sucuriscan_logs4report" class="input-text" placeholder="e.g. 500" />
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Current Timezone</td>
            <td>%%SUCURI.CustomTimezone%% <em>(%%SUCURI.CurrentDatetime%%)</em></td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <a href="options-general.php" target="_blank" class="button">
                        <span>Change Timezone from the Settings/General page</span>
                    </a>
                </form>
            </td>
        </tr>

    </tbody>
</table>
