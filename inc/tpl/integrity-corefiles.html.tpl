
<div id="poststuff" class="sucuriscan-%%SUCURI.WordPress.UpdateVisibility%%">
    <div class="postbox sucuriscan-border sucuriscan-border-bad">
        <h3>WordPress version outdated</h3>

        <div class="inside">
            <p>
                The current version of your site was detected as
                <code>%%SUCURI.WordPress.Version%%</code> which is different to the official
                latest version. The integrity check can not run using this version number
                <a href="%%SUCURI.WordPress.UpgradeURL%%" target="_blank">update now</a> to
                be able to run the integrity check.
            </p>
        </div>
    </div>
</div>


<table class="wp-list-table widefat sucuriscan-table sucuriscan-table-double-title sucuriscan-corefiles sucuriscan-%%SUCURI.CoreFiles.Visibility%%">
    <tbody>
        <tr><th>Core files added (%%SUCURI.CoreFiles.AddedCount%%)</th></tr>

        %%SUCURI.CoreFiles.Added%%

        <tr><th>Core files removed (%%SUCURI.CoreFiles.RemovedCount%%)</th></tr>

        %%SUCURI.CoreFiles.Removed%%

        <tr><th>Core files modified (%%SUCURI.CoreFiles.ModifiedCount%%)</th></tr>

        %%SUCURI.CoreFiles.Modified%%
    </tbody>
</table>
