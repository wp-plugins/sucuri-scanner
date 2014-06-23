
<div class="wrap sucuriscan-wrap">

    <h2 id="warnings_hook"></h2>

    <div class="sucuriscan-header sucuriscan-clearfix">
        <a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security" class="sucuriscan-logo">
            <img src="%%SUCURI.SucuriURL%%/inc/images/logo.png" alt="Sucuri Security" />
        </a>
        <h2>SiteCheck Scanner %%SUCURI.PageTitle%%</h2>
    </div>

    <h2 class="nav-tab-wrapper">
        %%SUCURI.Navbar%%
    </h2>

    <div class="sucuriscan-maincontent sucuriscan-clearfix">

        <div class="sucuriscan-leftside sucuriscan-%%SUCURI.PageStyleClass%%">

            <div class="sucuriscan-getapi-div sucuriscan-clearfix sucuriscan-%%SUCURI.GetApiFormVisibility%%">
                <p>
                    In order to enable audit logs, integrity checking and email alerts, you need to
                    generate an API key that will communicate with the Sucuri Servers.
                </p>

                <form action="%%SUCURI.URL.Settings%%" method="post" class="sucuriscan-getapi-form">
                    <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                    <button type="submit" name="sucuriscan_get_api_key" class="button-primary">
                        <span class="sucuriscan-button-title">Generate API key</span>
                        <span class="sucuriscan-button-subtitle">for <b>%%SUCURI.CleanDomain%%</b> / <b>%%SUCURI.AdminEmail%%</b></span>
                    </button>
                </form>
            </div>

            %%SUCURI.PageContent%%

        </div>

        <div class="sucuriscan-sidebar">

            <div class="sucuriscan-ad">
                <h2>Is your website infected with malware? Blacklisted by Google?</h2>
                <p>Don't know where to start? Get cleared today by <a href="http://sucuri.net/signup">Sucuri Security</a>!</p>
                <p><a href="http://sucuri.net/tour" target="_blank" class="button-primary">Read more &#187;</a></p>
            </div>

            <div class="sucuriscan-ad">
                <h2>Preventive website security in the cloud!</h2>
                <ul class="sucuri-list">
                    <li>Web Application Firewall (WAF) Protection</li>
                    <li>Virtual Website Patching</li>
                    <li>Cloud Intrusion Prevention System (IPS)</li>
                    <li>High Security Website Monitoring</li>
                    <li>Malicious Traffic Filtering</li>
                </ul>
                <p>
                    <a href="http://cloudproxy.sucuri.net/signup" target="_blank" class="button button-primary">Sign up now</a>
                    <a href="http://cloudproxy.sucuri.net/" target="_blank" class="button button-primary">Read more</a>
                </p>
            </div>

            <iframe src="https://www.youtube-nocookie.com/embed/EVa9FY3nKuQ" height="250" class="sucuriscan-scanner-video" allowfullscreen></iframe>

        </div>

    </div>

    <div class="sucuriscan-footer sucuriscan-clearfix">
        <a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security" class="sucuriscan-logo">
            <img src="%%SUCURI.SucuriURL%%/inc/images/logo.png" alt="Sucuri Security" />
        </a>
        <div class="sucuriscan-help">
            <p>
                If you have any questions about these checks or this plugin, contact us at
                <a href="mailto:info@sucuri.net">info@sucuri.net</a> or visit
                <a href="http://sucuri.net/" target="_blank">sucuri.net</a>
            </p>
        </div>
    </div>
</div>
