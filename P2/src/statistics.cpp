#include <iostream>
#include <thread>
#include <atomic>
#include <httplib.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include "PacketCapture.h"
#include "PacketAnalyzer.h"

using namespace std;
using namespace httplib;

// ----------------- shared Reports -----------------
DnsReport dnsrep;
HttpReport httprep;
SipReport siprep;

Report sharedrep;

// ----------------- metrics Server -----------------
std::string generateMetrics() {
    std::string out;

    out += "# HELP packets_received Total packets received\n";
    out += "# TYPE packets_received counter\n";
    out += "packets_received " + std::to_string(sharedrep.recieved.load()) + "\n";

    out += "# HELP dns_total Total DNS transactions\n";
    out += "# TYPE dns_total counter\n";
    out += "dns_total " + std::to_string(sharedrep.dnsreport->totalDns.load()) + "\n";
    out += "# HELP dns_success Successful DNS transactions\n";
    out += "# TYPE dns_success counter\n";
    out += "dns_success " + std::to_string(sharedrep.dnsreport->successDns.load()) + "\n";
    out += "# HELP dns_failed Failed DNS transactions\n";
    out += "# TYPE dns_failed counter\n";
    out += "dns_failed " + std::to_string(sharedrep.dnsreport->failedDns.load()) + "\n";

    out += "# HELP http_total Total HTTP transactions\n";
    out += "# TYPE http_total counter\n";
    out += "http_total " + std::to_string(sharedrep.httpreport->totalHttp.load()) + "\n";
    out += "# HELP http_success Successful HTTP transactions\n";
    out += "# TYPE http_success counter\n";
    out += "http_success " + std::to_string(sharedrep.httpreport->successHttp.load()) + "\n";
    out += "# HELP http_failed Failed HTTP transactions\n";
    out += "# TYPE http_failed counter\n";
    out += "http_failed " + std::to_string(sharedrep.httpreport->failedHttp.load()) + "\n";

    out += "# HELP sip_total Total SIP transactions\n";
    out += "# TYPE sip_total counter\n";
    out += "sip_total " + std::to_string(sharedrep.sipreport->totalSip.load()) + "\n";
    out += "# HELP sip_success Successful SIP transactions\n";
    out += "# TYPE sip_success counter\n";
    out += "sip_success " + std::to_string(sharedrep.sipreport->successSip.load()) + "\n";
    out += "# HELP sip_failed Failed SIP transactions\n";
    out += "# TYPE sip_failed counter\n";
    out += "sip_failed " + std::to_string(sharedrep.sipreport->failedSip.load()) + "\n";

    return out;
}

void startMetricsServer(int port = 8080) {
    Server svr;

    svr.Get("/metrics", [](const Request&, Response& res) {
        res.set_content(generateMetrics(), "text/plain; version=0.0.4");
    });

    cout << "Prometheus metrics server running on port " << port << endl;
    svr.listen("0.0.0.0", port);
}

int main(int argc, char* argv[])
{
    sharedrep.dnsreport = &dnsrep;
    sharedrep.httpreport = &httprep;
    sharedrep.sipreport = &siprep;

    Reporter reporter(sharedrep); // wraps the analyzers

    PacketCapture cap;
    Binary bin;

    int reportBuff = 10; // default: every 10 packets
    if(argc > 1)
        reportBuff = stoi(argv[1]);


    string interface = "eth0"; // default interface
    if(argc > 2)
        interface = argv[2];

    // start prometheus HTTP server on a separate thread
    thread metricsThread(startMetricsServer, 8080);
    metricsThread.detach();

    if (!cap.openInterface(interface)) { 
        cerr << "Failed to open interface or file!" << endl;
        return 1;
    }

    cout << "Starting packet capture..." << endl;
    while (cap.getNextPacket(bin))
    {
        reporter.addBinary(bin);
        if (sharedrep.recieved.load() % reportBuff == 0) {
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
