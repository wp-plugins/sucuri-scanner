
<script type="text/javascript">
jQuery(document).ready(function(){
    var jq = jQuery;
    if( jq('.sucuriscan-tabs').length ){
        var hidden_class = 'sucuriscan-hidden';
        var active_class = 'sucuriscan-tab-active';

        jq('.sucuriscan-tabs > ul a').on('click', function(e){
            e.preventDefault();

            var button = jq(this);
            var container_id = button.data('tabname');
            var container = jq('.sucuriscan-tab-containers > #sucuriscan-'+container_id);

            if( container.length ){
                jq('.sucuriscan-tabs > ul a').removeClass(active_class);
                jq('.sucuriscan-tab-containers > div').addClass(hidden_class);
                button.addClass(active_class);
                container.removeClass(hidden_class)
            }
        });

        jq('.sucuriscan-tab-containers > div').addClass(hidden_class);
        jq('.sucuriscan-tabs > ul li:first-child a').trigger('click');
    }
});
</script>

<div class="sucuriscan-tabs">
    <ul>
        <li>
            <a href="#" data-tabname="server-info">Plugin & Server Info</a>
        </li>
        <li>
            <a href="#" data-tabname="loggedin-users">Logged In Users</a>
        </li>
        <li>
            <a href="#" data-tabname="wordpress-cronjobs">WordPress Cronjobs</a>
        </li>
        <li>
            <a href="#" data-tabname="htaccess-integrity">HTAccess Integrity</a>
        </li>
        <li>
            <a href="#" data-tabname="wpconfig-vars">WP Config Variables</a>
        </li>
    </ul>

    <div class="sucuriscan-tab-containers">
        <div id="sucuriscan-server-info">
            %%SUCURI.ServerInfo%%
        </div>

        <div id="sucuriscan-loggedin-users">
            %%SUCURI.LoggedInUsers%%
        </div>

        <div id="sucuriscan-wordpress-cronjobs">
            %%SUCURI.Cronjobs%%
        </div>

        <div id="sucuriscan-htaccess-integrity">
            %%SUCURI.HTAccessIntegrity%%
        </div>

        <div id="sucuriscan-wpconfig-vars">
            %%SUCURI.WordpressConfig%%
        </div>
    </div>
</div>
