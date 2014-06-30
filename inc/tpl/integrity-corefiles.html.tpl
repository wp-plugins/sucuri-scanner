
<table class="wp-list-table widefat sucuriscan-table sucuriscan-corefiles sucuriscan-%%SUCURI.CoreFiles.Visibility%%">
    <thead>
        <tr>
            <th class="sucuriscan-clearfix thead-with-button">
                <span>WordPress core files integrity (%%SUCURI.CoreFiles.ListCount%% files)</span>
                <div class="sucuriscan-pull-right sucuriscan-corefiles-abbrs">
                    <span class="sucuriscan-status-type sucuriscan-status-added">Added</span>
                    <span class="sucuriscan-status-type sucuriscan-status-modified">Modified</span>
                    <span class="sucuriscan-status-type sucuriscan-status-removed">Removed</span>
                    <button id="sucuriscan-corefiles-show" class="button button-primary thead-topright-action" data-action="show">Show files</button>
                </div>
            </th>
        </tr>

        <tr>
            <td class="sucuriscan-corefiles-warning">
                <p>
                    The integrity of your WordPress installation is not good. There are files that
                    were added, modified, and/or removed in the core directories <code>/&lt;root&gt;</code>,
                    <code>/wp-admin</code> and/or <code>/wp-includes</code>.
                </p>
            </td>
        </tr>
    </thead>

    <tbody>

        %%SUCURI.CoreFiles.List%%
    </tbody>
</table>
