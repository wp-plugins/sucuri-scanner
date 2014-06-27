
<div id="poststuff">

    <div class="postbox sucuriscan-monitoring-instructions sucuriscan-%%SUCURI.Monitoring.InstructionsVisibility%%">
        <h3>Instructions to enable CloudProxy WAF</h3>

        <div class="inside">
            <p>
                A powerful <b>WAF</b> <em>(Web Application Firewall)</em> and <b>Intrusion Prevention</b>
                system for any WordPress user. If you do not have an account, you can sign up for one here:
                <a href="http://cloudproxy.sucuri.net/" target="_blank">Sucuri CloudProxy</a>
            </p>

            <ol>
                <li>
                    Sign up for a Sucuri CloudProxy account here:
                    <a href="https://login.sucuri.net/signup2/create?CloudProxy" target="_blank">Sign up</a>
                </li>
                <li>
                    Change your DNS to point your site to one of our servers. This link explains
                    <a href="https://dashboard.sucuri.net/cloudproxy/" target="_blank"> CloudProxy Dashboard</a>
                    or use our documentation here <a href="http://kb.sucuri.net/cloudproxy" target="_blank">
                    KB CloudProxy</a>.
                </li>
                <li>You are all set. There is nothing else to do.</li>
            </ol>

            <p>
                Once enabled, our firewall will act as a shield, protecting your site from attacks
                and preventing malware infections and reinfections. It will block SQL injection attempts,
                brute force attacks, XSS, RFI, backdoors and many other threats against your site.
            </p>
        </div>
    </div>


    <div class="sucuriscan-tabs">
        <ul>
            <li>
                <a href="#" data-tabname="monitoring-settings">Firewall (WAF) Settings</a>
            </li>
            <li>
                <a href="#" data-tabname="monitoring-logs">Firewall (WAF) Logs</a>
            </li>
        </ul>

        <div class="sucuriscan-tab-containers">
            <div id="sucuriscan-monitoring-settings">
                %%SUCURI.Monitoring.Settings%%
            </div>

            <div id="sucuriscan-monitoring-logs">
                %%SUCURI.Monitoring.Logs%%
            </div>
        </div>
    </div>

</div>
