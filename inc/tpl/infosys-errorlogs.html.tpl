
<div id="poststuff">
    <div class="postbox sucuriscan-border sucuriscan-table-description sucuriscan-errorlogs">
        <h3>Error Logs</h3>

        <div class="inside">
            <p>
                Web servers like Apache, Nginx and others use files to record errors encountered
                during the execution of a dynamic language or the server processes. Depending on
                the configuration of the server, these files may be accessible from the web
                opening a hole in your site to allow an attacker to gather sensitive information
                of your project, so it is highly recommended to delete them.
            </p>

            <div class="sucuriscan-inline-alert-info">
                <p>
                    If you are a developer, you may want to check the latest errors encountered by
                    the server before delete the log file, that way you can see where the
                    application is failing and fix the errors. Note that many error log files may
                    have thousand of lines, so you will only see the latest entries to prevent PHP
                    interpreter to stop the execution of the parser when the maximum execution time
                    is reached.
                </p>
            </div>

            <div class="sucuriscan-inline-alert-error sucuriscan-%%SUCURI.ErrorLog.DisabledVisibility%%">
                <p>
                    The analysis of error logs is disabled, go to the <em>Scanner Settings</em>
                    panel in the <em>Settings</em> page to enable it.
                </p>
            </div>
        </div>
    </div>
</div>

<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-errorlogs-list">
    <thead>
        <tr>
            <th colspan="5" class="thead-with-button">
                <span>Error Logs (%%SUCURI.ErrorLog.FileSize%%)</span>

                <form action="%%SUCURI.URL.Hardening%%#error-logs" method="post" class="thead-topright-action">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_run_hardening" value="1" />
                    <input type="hidden" name="sucuriscan_harden_errorlog" value="Harden" />
                    <button type="submit" class="button-primary">Delete logs</button>
                </form>
            </th>
        </tr>

        <tr>
            <th width="100">Date Time</th>
            <th width="50">Type</th>
            <th>Error Message</th>
            <th width="300">File</th>
            <th width="50">Line</th>
        </tr>
    </thead>

    <tbody>
        %%SUCURI.ErrorLog.List%%

        <tr class="sucuriscan-%%SUCURI.ErrorLog.NoItemsVisibility%%">
            <td colspan="5">
                <em>No logs so far.</em>
            </td>
        </tr>
    </tbody>
</table>
