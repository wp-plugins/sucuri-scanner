
<div class="postbox sucuriscan-border sucuriscan-border-good sucuriscan-integrity-message sucuriscan-%%SUCURI.CoreFiles.GoodVisibility%%">
    <h3>WordPress core integrity</h3>

    <div class="inside">
        <p>
            The core files of your WordPress installation seem to match the version of the
            official repository according to the comparison made between the list of hashes
            gathered from scanning of your project and the official list of hashes provided
            by WordPress using the version number recognized in your installation.
        </p>
    </div>
</div>

<table class="wp-list-table widefat sucuriscan-table sucuriscan-corefiles sucuriscan-%%SUCURI.CoreFiles.BadVisibility%%">
    <thead>
        <tr>
            <th class="sucuriscan-clearfix thead-with-button">
                <span>WordPress core integrity (%%SUCURI.CoreFiles.ListCount%% files)</span>
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
                <div>
                    <p>
                        We detected changes in the integrity of your WordPress core files. There are files that
                        were added, modified, and/or removed in the core directories <code>/&lt;root&gt;</code>,
                        <code>/wp-admin</code> and/or <code>/wp-includes</code>.
                    </p>
                </div>
            </td>
        </tr>
    </thead>

    <tbody>

        %%SUCURI.CoreFiles.List%%
    </tbody>
</table>
