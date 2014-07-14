
<form action="%%SUCURI.URL.Posthack%%#database-backups" method="post">
    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
    <input type="hidden" name="sucuriscan_database_backup" value="1" />
    <input type="hidden" name="sucuriscan_process_form" value="1" />

    <table class="wp-list-table widefat">
        <thead>
            <tr>
                <th colspan="5" class="thead-with-button">
                    <span>Database Backups</span>
                    <div class="generate-dbbackup-form thead-topright-action">
                        <input type="submit" name="generate_dbbackup" value="Generate DB Backup" class="button button-primary" />
                    </div>
                </th>
            </tr>
            <tr>
                <th class="manage-column column-cb check-column">
                    <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                    <input id="cb-select-all-1" type="checkbox">
                </th>
                <th class="manage-column">Filename</th>
                <th class="manage-column">Type</th>
                <th class="manage-column">Size</th>
                <th class="manage-column">Date/Time</th>
            </tr>
        </thead>

        <tbody>
            %%SUCURI.BackupList%%
        </tbody>

        <tfoot>
            <tr>
                <td colspan="5">
                    <input type="submit" name="remove_dbbackup" value="Remove selected files" class="button button-primary" />
                </td>
            </tr>
        </tfoot>
    </table>
</form>
