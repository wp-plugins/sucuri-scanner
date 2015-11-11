
<div class="postbox">
    <h3>API Request Timeout</h3>

    <div class="inside">
        <p>
            The plugin sends the data of events triggered by WordPress when it considers
            the action is suspicious, it sends this information via HTTP requests using
            <a href="https://developer.wordpress.org/reference/functions/wp_remote_post/"
            target="_blank">built-in functions</a> provided by WordPress and waits some
            seconds <em>(90 by default)</em> to get a response.
        </p>

        <div class="sucuriscan-hstatus sucuriscan-hstatus-2">
            <span>Wait <b>%%SUCURI.RequestTimeout%%</b> before timeout</span>
        </div>

        <p>
            If you start experiencing issues related with the timeout of the requests
            you may consider to increase the number of seconds to wait for the response.
            You may also want to check with your hosting provider to see if there is
            something in the server blocking the connection.
        </p>

        <form action="%%SUCURI.URL.Settings%%" method="post">
            <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
            <span class="sucuriscan-input-group">
                <label>HTTP Request Timeout (in secs)</label>
                <input type="text" name="sucuriscan_request_timeout" class="input-text" />
            </span>
            <button type="submit" class="button-primary">Proceed</button>
        </form>
    </div>
</div>
