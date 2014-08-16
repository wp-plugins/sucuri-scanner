
<div id="poststuff">
    <div class="postbox sucuriscan-border sucuriscan-table-description">
        <h3>Ignored Files (%%SUCURI.IgnoredFiles.Total%% files)</h3>

        <div class="inside">
            <p>
                These files will be ignored from the integrity checks, files marked with the
                letter <b>F</b> were added automatically by the plugin because they are
                considered as <em>false/positive</em>; files marked with an <b>A</b>, <b>M</b>,
                and <b>R</b> were <b>Added</b>, <b>Modified</b>, and <b>Removed</b> respectively.
            </p>

            <div class="sucuriscan-inline-alert-warning">
                <p>
                    Note that you can select multiple files and remove them definitely from your
                    site, or force the plugin to not ignore them, but files marked as
                    <em>false/positive</em> will always be considered as that and ignored every
                    time.
                </p>
            </div>
        </div>
    </div>
</div>

<form action="%%SUCURI.URL.Home%%#ignored-files" method="post">
    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />

    <table class="wp-list-table widefat sucuriscan-table sucuriscan-ignoredfiles">
        <thead>
            <tr>
                <th class="manage-column column-cb check-column">
                    <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                    <input id="cb-select-all-1" type="checkbox">
                </th>
                <th width="70" class="manage-column">Status</th>
                <th width="140" class="manage-column">Added at</th>
                <th class="manage-column">Filepath</th>
            </tr>
        </thead>

        <tbody>
            %%SUCURI.IgnoredFiles.List%%
        </tbody>

        <tfoot>
            <tr>
                <td colspan="4">
                    <label>
                        <select name="sucuriscan_ignored_file_action">
                            <option value="">Choose action</option>
                            <option value="unignore">Do not ignore</option>
                            <option value="remove">Remove file(s)</option>
                        </select>
                    </label>

                    <button type="submit" class="button button-primary">Send action</button>
                </td>
            </tr>
        </tfoot>
    </table>

</form>
