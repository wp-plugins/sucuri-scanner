
<div id="poststuff">
    <div class="postbox sucuriscan-border sucuriscan-table-description">
        <h3>Scanner Settings</h3>

        <div class="inside">
            <p>
                There are multiple scanners implemented in the code of the plugin, all of them
                are enabled by default and you can deactivate them separately without affect the
                others. You may want to disable a scanner because your site has too many
                directories and/or files to scan, or because the maximum quantity of memory
                allowed for your project is not enough to execute one these functions. You can
                enable and disable any of the scanners anything you want.
            </p>

            <div class="sucuriscan-inline-alert-info">
                <p>
                    The <em>Scanning Interface</em> is the method that will be used internally to
                    retrieve the diretories and files inside the project when the file system
                    scanners are executed. In the best case <strong>SPL</strong> will be enough
                    <em>(and it is the default option)</em>, but with older versions of PHP you may
                    need to choose a different method like <strong>OpenDir</strong> or
                    <strong>Glob</strong> which provide the same results.
                </p>
            </div>
        </div>
    </div>
</div>

<table class="wp-list-table widefat sucuriscan-table sucuriscan-settings sucuriscan-settings-scanner">
    <thead>
        <tr>
            <th>Option</th>
            <th>Value</th>
            <th>&nbsp;</th>
        </tr>
    </thead>

    <tbody>
        <tr class="alternate">
            <td>Filesystem scanner</td>
            <td>%%SUCURI.FsScannerStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_fs_scanner" value="%%SUCURI.FsScannerSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.FsScannerSwitchCssClass%%">%%SUCURI.FsScannerSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Scan modified files</td>
            <td>%%SUCURI.ScanModfilesStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_scan_modfiles" value="%%SUCURI.ScanModfilesSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.ScanModfilesSwitchCssClass%%">%%SUCURI.ScanModfilesSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>Integrity checking</td>
            <td>%%SUCURI.ScanChecksumsStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_scan_checksums" value="%%SUCURI.ScanChecksumsSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.ScanChecksumsSwitchCssClass%%">%%SUCURI.ScanChecksumsSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Ignore some files</td>
            <td>%%SUCURI.IgnoreScanningStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_ignore_scanning" value="%%SUCURI.IgnoreScanningSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.IgnoreScanningSwitchCssClass%%">%%SUCURI.IgnoreScanningSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>Scan error log files</td>
            <td>%%SUCURI.ScanErrorlogsStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_scan_errorlogs" value="%%SUCURI.ScanErrorlogsSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.ScanErrorlogsSwitchCssClass%%">%%SUCURI.ScanErrorlogsSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Parse error logs</td>
            <td>%%SUCURI.ParseErrorLogsStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_parse_errorlogs" value="%%SUCURI.ParseErrorLogsSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.ParseErrorLogsSwitchCssClass%%">%%SUCURI.ParseErrorLogsSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>SiteCheck scanner</td>
            <td>%%SUCURI.SiteCheckScannerStatus%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_sitecheck_scanner" value="%%SUCURI.SiteCheckScannerSwitchValue%%" />
                    <button type="submit" class="button-primary %%SUCURI.SiteCheckScannerSwitchCssClass%%">%%SUCURI.SiteCheckScannerSwitchText%%</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>SiteCheck counter</td>
            <td><span class="sucuriscan-monospace">%%SUCURI.SiteCheckCounter%% scans so far</span></td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Scanner%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="hidden" name="sucuriscan_malware_scan" value="1" />
                    <button type="submit" class="button-primary">Force Scan</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>Last Scanning</td>
            <td><span class="sucuriscan-monospace">%%SUCURI.ScanningRuntimeHuman%%</span></td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Home%%" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_force_scan" class="button-primary">Force Scan</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Scanning frequency</td>
            <td>%%SUCURI.ScanningFrequency%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_scan_frequency">
                        %%SUCURI.ScanningFrequencyOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr class="alternate">
            <td>Scanning interface</td>
            <td>%%SUCURI.ScanningInterface%%</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <select name="sucuriscan_scan_interface">
                        %%SUCURI.ScanningInterfaceOptions%%
                    </select>
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

        <tr>
            <td>Error logs limit</td>
            <td>%%SUCURI.ErrorLogsLimit%% last lines</td>
            <td class="td-with-button">
                <form action="%%SUCURI.URL.Settings%%#settings-scanner" method="post">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <input type="text" name="sucuriscan_errorlogs_limit" placeholder="Number of lines to analyze" class="input-text" />
                    <button type="submit" class="button-primary">Change</button>
                </form>
            </td>
        </tr>

    </tbody>
</table>
