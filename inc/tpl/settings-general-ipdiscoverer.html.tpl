
<div class="postbox">
    <h3>IP Address Discoverer</h3>

    <div class="inside">
        <p>
            The IP address discoverer will use DNS lookups to automatically detect if the
            website is behind <a href="https://sucuri.net/website-firewall/"
            target="_blank">CloudProxy</a> in which case will modify the global server
            variable <em>Remote-Addr</em> to set the real IP of the website's visitors. This
            check runs on every WordPress init action and that is why it may slow down your
            website as some hosting providers rely on slow DNS servers which makes the
            operation take more time than it should.
        </p>

        <div class="sucuriscan-inline-alert-warning">
            <p>
                <b>IMPORTANT:</b> This option <em>(if enabled)</em> may slow down your website.
            </p>
        </div>

        <div class="sucuriscan-hstatus sucuriscan-hstatus-2">
            <span>IP Address Discoverer is %%SUCURI.DnsLookupsStatus%%</span>

            <form action="%%SUCURI.URL.Settings%%" method="post">
                <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                <input type="hidden" name="sucuriscan_dns_lookups" value="%%SUCURI.DnsLookupsSwitchValue%%" />
                <button type="submit" class="button-primary %%SUCURI.DnsLookupsSwitchCssClass%%">
                    %%SUCURI.DnsLookupsSwitchText%%
                </button>
            </form>
        </div>

        <p>
            If you are experiencing issues with the automatic detection of IP address of
            your visitors, with the security logs, or with the response time of your website
            please send an email to <a href="mailto:info@sucuri.net">info@sucuri.net</a>
            explaining the situation and attach the information displayed below, this may
            help to troubleshoot the issue more easily; alternatively you may also ask for
            help in the forums.
        </p>

        <div class="sucuriscan-hstatus sucuriscan-hstatus-2 sucuriscan-monospace">
            <div>CloudProxy is %%SUCURI.IsUsingCloudProxy%%</div>
            <div>Website URL: %%SUCURI.WebsiteURL%%</div>
            <div>Top Level Domain: %%SUCURI.TopLevelDomain%%</div>
            <div>Website Hostname: %%SUCURI.WebsiteHostName%%</div>
            <div>Website Host Address: %%SUCURI.WebsiteHostAddress%%</div>
            <div>IP Address: %%SUCURI.RemoteAddress%% (%%SUCURI.RemoteAddressHeader%%)</div>
        </div>
    </div>
</div>
