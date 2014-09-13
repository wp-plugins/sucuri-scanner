
<div id="poststuff">
    <div class="postbox sucuriscan-border sucuriscan-table-description">
        <h3>Ignore Scanning</h3>

        <div class="inside">
            <p>
                If your project has too many directories and/or files it may cause the file
                system scanners to fail, you may want to increase the maximum execution time of
                the PHP scripts and the memory limit to allow the functions executed during the
                file system scans to finish successfully. If you do not want or do not have
                sufficient privileges to increase these values then you may want to skip some
                directories, this will force the plugin to ignore the files inside these
                folders.
            </p>
        </div>
    </div>
</div>

<form action="%%SUCURI.URL.Settings%%#settings-ignorescanning" method="post">
    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />

    <table class="wp-list-table widefat sucuriscan-table sucuriscan-settings-ignorescanning">
        <thead>
            <th class="manage-column column-cb check-column">
                <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                <input id="cb-select-all-1" type="checkbox">
            </th>
            <th class="manage-column" width="80">Ignored</th>
            <th class="manage-column">Directory</th>
            <th class="manage-column" width="180">Ignored At</th>
        </thead>

        <tbody>
            %%SUCURI.IgnoreScanning.ResourceList%%
        </tbody>

        <tfoot>
            <tr>
                <td colspan="4">
                    <p>
                        Selecting one or more directories from the list will force the plugin to ignore
                        the monitoring of the sub-folders and files inside these directories during the
                        execution of any of the file system scanners. This will applies to all the
                        scanners <em>(general scanner, modified files, integrity checks, error
                        logs)</em>.
                    </p>

                    <label>
                        <select name="sucuriscan_ignorescanning_action">
                            <option value="">Choose action</option>
                            <option value="ignore">Ignore items</option>
                            <option value="unignore">Un-ignore items</option>
                        </select>
                    </label>

                    <button type="submit" class="button button-primary">Send action</button>
                </td>
            </tr>
        </tfoot>
    </table>
</form>
