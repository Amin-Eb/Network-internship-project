#include <iostream>
#include <atomic>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include "PacketCapture.h"
#include "PacketAnalyzer.h"

using namespace std;
using namespace prometheus;

// ----------------- shared Reports -----------------
DnsReport dnsrep;
HttpReport httprep;
SipReport siprep;

Report sharedrep;

// ----------------- Prometheus -----------------
//faild fields may go up or down so we need gauge, others are just up so counters are enough.


shared_ptr<Registry> registry = make_shared<Registry>();

auto& dns_total = BuildCounter()
    .Name("dns_total")
    .Help("Total DNS transactions")
    .Register(*registry);

auto& dns_success = BuildCounter()
    .Name("dns_success")
    .Help("Successful DNS transactions")
    .Register(*registry);

auto& dns_failed = BuildGauge()
    .Name("dns_failed")
    .Help("Failed DNS transactions")
    .Register(*registry);

auto& http_total = BuildCounter()
    .Name("http_total")
    .Help("Total HTTP transactions")
    .Register(*registry);

auto& http_success = BuildCounter()
    .Name("http_success")
    .Help("Successful HTTP transactions")
    .Register(*registry);

auto& http_failed = BuildGauge()
    .Name("http_failed")
    .Help("Failed HTTP transactions")
    .Register(*registry);

auto& sip_total = BuildCounter()
    .Name("sip_total")
    .Help("Total SIP transactions")
    .Register(*registry);

auto& sip_success = BuildCounter()
    .Name("sip_success")
    .Help("Successful SIP transactions")
    .Register(*registry);

auto& sip_failed = BuildGauge()
    .Name("sip_failed")
    .Help("Failed SIP transactions")
    .Register(*registry);

auto& packets_received = BuildCounter()
    .Name("packets_received")
    .Help("Total packets received")
    .Register(*registry);

auto& dns_total_counter = dns_total.Add({});
auto& dns_success_counter = dns_success.Add({});
auto& dns_failed_counter = dns_failed.Add({});

auto& http_total_counter = http_total.Add({});
auto& http_success_counter = http_success.Add({});
auto& http_failed_counter = http_failed.Add({});

auto& sip_total_counter = sip_total.Add({});
auto& sip_success_counter = sip_success.Add({});
auto& sip_failed_counter = sip_failed.Add({});

auto& packets_received_counter = packets_received.Add({});

int main(int argc, char* argv[])
{
    sharedrep.dnsreport = &dnsrep;
    sharedrep.httpreport = &httprep;
    sharedrep.sipreport = &siprep;

    Reporter reporter(sharedrep);

    PacketCapture cap;
    Binary bin;

    int reportBuff = 10; // update every 10 packets for default
    if (argc > 1)
        reportBuff = stoi(argv[1]);

    string interface = "eth0"; // default interface
    if (argc > 2)
        interface = argv[2];

    // Start Prometheus metrics HTTP server
    Exposer exposer{"0.0.0.0:8080"};
    exposer.RegisterCollectable(registry);

    if (!cap.openInterface(interface)) {
        cerr << "Failed to open interface or file!" << endl;
        return 1;
    }


    //old values
    int dns_s = 0, dns_t = 0;
    int htt_s = 0, htt_t = 0;
    int sip_s = 0, sip_t = 0;
    int rec = 0;

    cout << "Starting packet capture..." << endl;

    while (cap.getNextPacket(bin))
    {
        reporter.addBinary(bin);

        if (sharedrep.recieved.load() % reportBuff == 0)
        {
            packets_received_counter.Increment( sharedrep.recieved.load() - rec); rec =  sharedrep.recieved.load();

            dns_total_counter.Increment(sharedrep.dnsreport->totalDns.load() - dns_t); dns_t = sharedrep.dnsreport->totalDns.load();
            dns_success_counter.Increment(sharedrep.dnsreport->successDns.load() - dns_s); dns_s = sharedrep.dnsreport->successDns.load();
            dns_failed_counter.Set(sharedrep.dnsreport->failedDns.load());

            http_total_counter.Increment(sharedrep.httpreport->totalHttp.load() - htt_t); htt_t = sharedrep.httpreport->totalHttp.load();
            http_success_counter.Increment(sharedrep.httpreport->successHttp.load() - htt_s); htt_s = sharedrep.httpreport->successHttp.load();
            http_failed_counter.Set(sharedrep.httpreport->failedHttp.load());

            sip_total_counter.Increment(sharedrep.sipreport->totalSip.load() - sip_t); sip_t = sharedrep.sipreport->totalSip.load();
            sip_success_counter.Increment(sharedrep.sipreport->successSip.load() - sip_s); sip_s = sharedrep.sipreport->successSip.load();
            sip_failed_counter.Set(sharedrep.sipreport->failedSip.load());
            
             cout << "[INFO] " << sharedrep.recieved.load() << " packets processed." << endl;
            cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
            cout << sharedrep.dnsreport->failedDns.load() << " DNS failed / "
                << sharedrep.dnsreport->successDns.load() << " DNS success / "
                << sharedrep.dnsreport->totalDns.load() << " DNS total\n";
            cout << sharedrep.httpreport->failedHttp.load() << " HTTP failed / "
                << sharedrep.httpreport->successHttp.load() << " HTTP success / "
                << sharedrep.httpreport->totalHttp.load() << " HTTP total\n";   
            cout << sharedrep.sipreport->failedSip.load() << " SIP failed / "
                << sharedrep.sipreport->successSip.load() << " SIP success / "
                << sharedrep.sipreport->totalSip.load() << " SIP total\n";
            // metrics are already atomic, Prometheus can scrape anytime
        }

        delete[] bin.data;
    }

    cap.close();
    cout << "Capture finished." << endl;
    return 0;
}
