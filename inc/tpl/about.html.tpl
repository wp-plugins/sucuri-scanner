<div class="wrap">
    <h2 id="warnings_hook"></h2>
    <div class="sucuriscan_header">
        <a href="http://sucuri.net/signup" target="_blank" title="Sucuri Security">
            <img src="%%SUCURI.SucuriURL%%/inc/images/logo.png" alt="Sucuri Security" />
        </a>
        <h2>Sucuri Security WordPress Plugin (About)</h2>
    </div>

    <div class="postbox-container" style="width:75%;">
        <div class="sucuriscan-maincontent">
            <div id="poststuff">
                <div class="postbox">
                    <h3>About</h3>
                    <div class="inside">
                        <p>
                        Our WordPress Security Plugin will monitor your site from the inside, creating
                        a complete audit trail, alerting you of possible security issues (file changes,
                        password guessing attacks, etc) and blocking the attackers. This is the perfect
                        complement for our external security scans.
                        </p>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <table class="wp-list-table widefat sucuriscan-about-list sucuri-%%SUCURI.SettingsDisplay%%">
                <thead>
                    <tr>
                        <th colspan="2">Plugin & Server Information</th>
                    </tr>
                </thead>

                <tbody>
                    <tr><td>Sucuri Plugin version</td><td>%%SUCURI.PluginVersion%%</td></li>
                    <tr><td>Sucuri Plugin MD5Sum (sucuri.php)</td><td>%%SUCURI.PluginMD5%%</td></li>
                    <tr><td>Sucuri Plugin Last-time scan</td><td>%%SUCURI.PluginRuntimeDatetime%%</td></li>
                    <tr><td>Operating System</td><td>%%SUCURI.OperatingSystem%%</td></li>
                    <tr><td>Server</td><td>%%SUCURI.Server%%</td></li>
                    <tr><td>Memory usage</td><td>%%SUCURI.MemoryUsage%%</td></li>
                    <tr><td>MYSQL Version</td><td>%%SUCURI.MySQLVersion%%</td></li>
                    <tr><td>SQL Mode</td><td>%%SUCURI.SQLMode%%</td></li>
                    <tr><td>PHP Version</td><td>%%SUCURI.PHPVersion%%</td></li>
                    <tr><td>PHP Safe Mode</td><td>%%SUCURI.SafeMode%%</td></li>
                    <tr><td>PHP Allow URL fopen</td><td>%%SUCURI.AllowUrlFopen%%</td></li>
                    <tr><td>PHP Memory Limit</td><td>%%SUCURI.MemoryLimit%%</td></li>
                    <tr><td>PHP Max Upload Size</td><td>%%SUCURI.UploadMaxFilesize%%</td></li>
                    <tr><td>PHP Max Post Size</td><td>%%SUCURI.PostMaxSize%%</td></li>
                    <tr><td>PHP Max Script Execute Time</td><td>%%SUCURI.MaxExecutionTime%%</td></li>
                    <tr><td>PHP Max Input Time</td><td>%%SUCURI.MaxInputTime%%</td></li>
                </tbody>
            </table>

            <table class="wp-list-table widefat sucuriscan-wpcron-list sucuri-%%SUCURI.SettingsDisplay%%">
                <thead>
                    <tr>
                        <th colspan="4">Wordpress Cronjobs</th>
                    </tr>
                    <tr>
                        <th>Task</th>
                        <th>Schedule</th>
                        <th>Next due (GMT/UTC)</th>
                        <th>Wordpress Hook</th>
                        <!-- <th>Hook arguments</th> -->
                    </tr>
                </thead>

                <tbody>
                    %%SUCURI.Cronjobs%%
                </tbody>
            </table>

            <div id="poststuff">
                <div class="postbox">
                    <h3>How does it work?</h3>
                    <div class="inside">
                        <ul>
                            <li>Web Application Firewall. Block attacks before they reach your site.</li>
                            <li>Integrity Monitoring. Receive notifications if any of your files are modified.</li>
                            <li>Audit Logs. Keep track of everything that happens inside WordPress, including new users, posts, login failures and successful logins.</li>
                            <li>Activity Reporting</li>
                            <li>1-click Hardening. Easy-to-use hardening options for your site.</li>
                        </ul>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <div id="poststuff">
                <div class="postbox">
                    <h3>Web Application Firewall (WAF)</h3>
                    <div class="inside">
                        <p>
                        The WAF is a unique feature that is designed to intelligently protect your sites
                        from brute-force attacks like dictionary attacks and other similar unauthorized
                        access attempts. When a bad IP is identified it is blacklisted in your admin
                        dashboard. If it was an unintentional block, you have the ability to white-list
                        access to any IP.
                        </p>
                        <p>
                        The WAF is not tied to your application, it communicates with our servers and
                        allows us to see malicious attacks across the network. When one client gets attacked
                        by one bad IP in Croatia, we are able to push preventive measures to every plugin
                        to protect against that IP.
                        </p>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <div id="poststuff">
                <div class="postbox">
                    <h3>Integrity Monitoring</h3>
                    <div class="inside">
                        <p>
                        This feature compares your core install against a clean version of core. In other
                        words, if it is not a 1-to-1 match with core you will be notified of a problem.
                        Future add-ons include:
                        </p>
                        <ul>
                            <li>Theme Integrity Checks</li>
                            <li>Plugin Integrity Checks</li>
                            <li>Third-party Integrity Checks</li>
                        </ul>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <div id="poststuff">
                <div class="postbox">
                    <h3>Audit Trails</h3>
                    <div class="inside">
                        <p>
                        This feature is great for proactive webmasters who want to monitor their website
                        to ensure no unauthorized access or changes are made without prior approval.
                        Monitor your site for changes. This feature monitors for a large number of actions,
                        including:
                        </p>
                        <ul>
                            <li>Login attempts</li>
                            <li>New Posts</li>
                            <li>Failed Logins</li>
                            <li>New Plugins</li>
                            <li>File Changes</li>
                            <li>New Users</li>
                            <li>New Attachments</li>
                            <li>Delete Actions (users and posts)</li>
                            <li>Revisions</li>
                        </ul>
                    </div>
                </div>
            </div><!-- End poststuff -->

            <div id="poststuff">
                <div class="postbox">
                    <h3>1-Click Hardening</h3>
                    <div class="inside">
                        <p>
                        In our experience a high-percentage of the infections we see every day come from
                        poor management on the end-user’s part. This feature uses common hardening
                        measures that can be taken at any time and helps reduce infection risk. This
                        feature performs the following:
                        </p>
                        <ul>
                            <li>Checks software core version</li>
                            <li>Hides your version (security through obscurity)</li>
                            <li>Upload directory protected</li>
                            <li>Secret keys and salts created</li>
                            <li>Configuration file hardening/location verification</li>
                            <li>Hardening of readme file</li>
                            <li>PHP verification</li>
                        </ul>
                    </div>
                </div>
            </div><!-- End poststuff -->

        </div><!-- End sucuriscan-maincontent -->
    </div><!-- End postbox-container -->

    %%SUCURI.SucuriWPSidebar%%

</div><!-- End wrap -->
