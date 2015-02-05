
<div class="postbox sucuriscan-border sucuriscan-border-good sucuriscan-integrity-message sucuriscan-%%SUCURI.CoreFiles.GoodVisibility%%">
    <span class="sucuriscan-integrity-mark">OK</span>
    <h3>Core integrity</h3>

    <div class="inside">
        <p>Your WordPress core files are clean and were not modified.</p>
    </div>
</div>

<form action="%%SUCURI.URL.Home%%" method="post">
    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />

    <table class="wp-list-table widefat sucuriscan-table sucuriscan-corefiles sucuriscan-%%SUCURI.CoreFiles.BadVisibility%%">
        <thead>
            <tr>
                <th colspan="4" class="sucuriscan-clearfix thead-with-button">
                    <span>Core integrity (%%SUCURI.CoreFiles.ListCount%% files)</span>
                    <button id="sucuriscan-corefiles-show" class="button button-primary thead-topright-action" data-action="show">Show files</button>
                </th>
            </tr>

            <tr>
                <td colspan="4" class="sucuriscan-corefiles-warning">
                    <div>
                        <p>
                            Changes in the integrity of your core files were detected. There are files that
                            were added, modified, and/or removed in the core directories <code>/&lt;root&gt;</code>,
                            <code>/wp-admin</code> and/or <code>/wp-includes</code>. You may want to check
                            each file to determine if they were infected with malicious code.
                        </p>
                    </div>
                </td>
            </tr>

            <tr class="sucuriscan-hidden">
                <th class="manage-column column-cb check-column">
                    <label class="screen-reader-text" for="cb-select-all-1">Select All</label>
                    <input id="cb-select-all-1" type="checkbox">
                </th>
                <th width="80" class="manage-column">Status</th>
                <th width="100" class="manage-column">File Size</th>
                <th class="manage-column">File Path</th>
            </tr>
        </thead>

        <tbody>
            %%SUCURI.CoreFiles.List%%
        </tbody>

        <tfoot>
            <tr>
                <td colspan="4">
                    <p>
                        The action to restore the content of a file will only work with files that were
                        <b>modified</b> or <b>removed</b>, for files that were <b>added</b> you must
                        either remove or mark as fixed. Files marked as <b>fixed</b> will always be
                        ignored from the integrity checks, an attacker can use this option to hide a
                        malicious file, so always check what files are being ignored.
                    </p>

                    <label>
                        <select name="sucuriscan_integrity_action">
                            <option value="">Choose action</option>
                            <option value="restore">Restore file(s) content</option>
                            <option value="delete">Delete file(s)</option>
                            <option value="fixed">Mark as fixed</option>
                        </select>
                    </label>

                    <button type="submit" class="button button-primary">Send action</button>
                </td>
            </tr>
        </tfoot>
    </table>

</form>
