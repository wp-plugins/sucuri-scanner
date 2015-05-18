
<div id="poststuff" class="sucuriscan-pattern-search">

    <div class="postbox">

        <div class="inside">

            <p>
                Backdoors may be installed in your website after an infection, if you are aware
                of an intrusion then this tool may help you to find the source of the malicious
                code among the files of your project. Note that this tool will not scan the
                database only the project files, you have to do check the database manually.
            </p>

            <div class="sucuriscan-inline-alert-warning">
                <p>
                    Due to the way PHP works is not possible to use this tool in an environment with
                    too many files, we will improve this tool as much as the language allow us but
                    there will always be a limit in the memory and execution time configured in the
                    server, we recommend to use this with caution.
                </p>
            </div>

            <form action="%%SUCURI.URL.Posthack%%#pattern-search" method="post">
                <input type="hidden" name="sucuriscan_page_nonce" value="%%SUCURI.PageNonce%%" />
                <input type="hidden" name="sucuriscan_reset_plugins" value="1" />

                <div class="sucuriscan-pattern-search-inputbox">
                    <input type="text" name="sucuriscan_pattern_search" placeholder="e.g. (M|m)alicious_Code_[0-9]{4,8}" class="sucuriscan-monospace input-text" />
                    <input type="button" value="Search" class="button button-primary input-button" />
                </div>
            </form>

            <script type="text/javascript">
            jQuery(function($){
                var sucuriscan_pattern_search_event = function(ev){
                    ev.preventDefault();

                    $('.sucuriscan-pattern-search form .input-text').attr('disabled', true);
                    $('.sucuriscan-pattern-search form .input-button').attr('disabled', true);
                    $('.sucuriscan-pattern-search .sucuriscan-table').removeClass('sucuriscan-hidden');

                    var query = $('.sucuriscan-pattern-search form .input-text').val();

                    $.post( '%%SUCURI.AjaxURL.Posthack%%', {
                        action: 'sucuriscan_posthack_ajax',
                        sucuriscan_page_nonce: '%%SUCURI.PageNonce%%',
                        form_action: 'pattern_search',
                        pattern: query,
                    }, function(data){
                        $('.sucuriscan-pattern-search .sucuriscan-table tbody').html( data );
                        $('.sucuriscan-pattern-search form .input-text').attr('disabled', false);
                        $('.sucuriscan-pattern-search form .input-button').attr('disabled', false);
                    });
                };

                $('.sucuriscan-pattern-search form').submit( sucuriscan_pattern_search_event );
                $('.sucuriscan-pattern-search form .input-button').click( sucuriscan_pattern_search_event );
            });
            </script>

            <table class="wp-list-table widefat sucuriscan-table sucuriscan-hidden">
                <thead>
                    <tr>
                        <th class="manage-column">Search Results</th>
                    </tr>
                </thead>

                <tbody>
                    <tr>
                        <td>
                            <span>Loading <em>(may take several seconds)</em>...</span>
                        </td>
                    </tr>
                </tbody>
            </table>

            <div>
                <a href="http://goo.gl/vEwZq6" target="_blank"
                class="button button-primary button-hero sucuriscan-cleanup-btn
                sucuriscan-btnblock">Request Professional Assistance from Sucuri</a>
            </div>

        </div>

    </div>

</div>
