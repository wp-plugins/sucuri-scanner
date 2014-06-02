/**
 * Sucuri Security - SiteCheck Malware Scanner
 * Copyright (C) 2010-2014 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */

function sucuriscan_alert_close(id){
    var element = document.getElementById('sucuri-alert-'+id);
    element.parentNode.removeChild(element);
}

jQuery(document).ready(function($){
    if( $('.sucuriscan-tabs').length ){
        var hidden_class = 'sucuriscan-hidden';
        var active_class = 'sucuriscan-tab-active';

        $('.sucuriscan-tabs > ul a').on('click', function(e){
            e.preventDefault();

            var button = $(this);
            var container_id = button.data('tabname');
            var container = $('.sucuriscan-tab-containers > #sucuriscan-'+container_id);

            if( container.length ){
                $('.sucuriscan-tabs > ul a').removeClass(active_class);
                $('.sucuriscan-tab-containers > div').addClass(hidden_class);
                button.addClass(active_class);
                container.removeClass(hidden_class)
            }
        });

        $('.sucuriscan-tab-containers > div').addClass(hidden_class);
        $('.sucuriscan-tabs > ul li:first-child a').trigger('click');
    }
});
