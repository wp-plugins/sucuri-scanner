
<div class="postbox sucuriscan-audit-report sucuriscan-border">
    <h3>Audit Report</h3>

    <div class="inside">

        <div class="sucuriscan-inline-alert-info">
            <p>
                The data used to generate these charts come from the last <strong>%%SUCURI.AuditReport.Logs4Report%%
                audit logs</strong> of your site, you can configure this number from the plugin
                settings. The categorization of each event may change at anytime but will be
                associated to the severity of the performed action, this means that an event
                generated after an user interaction <em>(authentications, database modifications,
                website options)</em> will always be more severe than a simple notification or a
                change in the plugin settings.
            </p>
        </div>

        <div class="sucuriscan-clearfix sucuriscan-report-row">

            <div class="sucuriscan-pull-left sucuriscan-report-chart">
                <div id="sucuriscan-report-events-per-type"></div>
            </div>

            <div class="sucuriscan-pull-right sucuriscan-report-chart">
                <div id="sucuriscan-report-events-per-login"></div>
            </div>

        </div>

        <div class="sucuriscan-clearfix sucuriscan-report-row">

            <div class="sucuriscan-pull-left sucuriscan-report-chart">
                <div id="sucuriscan-report-events-per-user"></div>
            </div>

            <div class="sucuriscan-pull-right sucuriscan-report-chart">
                <div id="sucuriscan-report-events-per-ipaddress"></div>
            </div>

        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($){

    /* Pie-chart with number of audit logs per event type. */
    $('#sucuriscan-report-events-per-type').highcharts({
        title: { text: 'Audit Logs per Event' },
        subtitle: { text: 'Source: http://sucuri.net/' },
        chart: { height: 300 },
        credits: { enabled: true },
        colors: [ %%SUCURI.AuditReport.EventColors%% ],
        plotOptions: {
            pie: {
                cursor: 'pointer',
                allowPointSelect: true,
                dataLabels: { enabled: false },
                showInLegend: true,
            }
        },
        legend: {
            enabled: true,
            align: 'right',
            layout: 'vertical',
            verticalAlign: 'middle',
        },
        series: [{
            type: 'pie',
            name: 'Events per Type',
            data: [ %%SUCURI.AuditReport.EventsPerType%% ]
        }]
    });

    /* Column-chart with number of audit logs per event login. */
    $('#sucuriscan-report-events-per-login').highcharts({
        title: { text: 'Successful/Failed Logins' },
        subtitle: { text: 'Source: http://sucuri.net/' },
        chart: { height: 300 },
        credits: { enabled: true },
        plotOptions: {
            pie: {
                cursor: 'pointer',
                allowPointSelect: true,
                dataLabels: { enabled: false },
                showInLegend: true,
            }
        },
        legend: {
            enabled: true,
            align: 'right',
            layout: 'vertical',
            verticalAlign: 'middle',
        },
        series: [{
            type: 'pie',
            name: 'Events per Login',
            data: [ %%SUCURI.AuditReport.EventsPerLogin%% ]
        }]
    });

    /* Bar-chart with number of audit logs per user account. */
    $('#sucuriscan-report-events-per-user').highcharts({
        title: { text: 'Audit Logs per User' },
        subtitle: { text: 'Source: http://sucuri.net/' },
        chart: { type: 'bar' },
        credits: { enabled: true },
        xAxis: {
            title: { text: 'User Accounts' },
            categories: [ %%SUCURI.AuditReport.EventsPerUserCategories%% ],
        },
        yAxis: {
            min: 0,
            labels: { overflow: 'justify' },
            title: {
                text: 'Events per User',
                align: 'high',
            },
        },
        legend: { enabled: false },
        plotOptions: {
            bar: {
                dataLabels: { enabled: true }
            }
        },
        series: [{
            name: 'Events per User',
            data: [ %%SUCURI.AuditReport.EventsPerUserSeries%% ]
        }]
    });

    /* Bar-chart with number of audit logs per remote address. */
    $('#sucuriscan-report-events-per-ipaddress').highcharts({
        title: { text: 'Audit Logs per IP Address' },
        subtitle: { text: 'Source: http://sucuri.net/' },
        chart: { type: 'bar' },
        credits: { enabled: true },
        xAxis: {
            title: { text: 'IP Addresses' },
            categories: [ %%SUCURI.AuditReport.EventsPerIPAddressCategories%% ],
        },
        yAxis: {
            min: 0,
            labels: { overflow: 'justify' },
            title: {
                text: 'Events per IP Address',
                align: 'high',
            },
        },
        legend: { enabled: false },
        plotOptions: {
            bar: {
                dataLabels: { enabled: true }
            }
        },
        series: [{
            name: 'Events per IP Address',
            data: [ %%SUCURI.AuditReport.EventsPerIPAddressSeries%% ]
        }]
    });

});
</script>
