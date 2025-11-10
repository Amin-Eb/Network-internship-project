#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include "PacketCapture.h"
#include "PacketAnalyzer.h"

using namespace std;
using namespace prometheus;

DnsReport dnsrep;
HttpReport httprep;
SipReport siprep;
Report sharedrep;

// ----------------- prometheus -----------------
shared_ptr<Registry> registry = make_shared<Registry>();

auto& dns_total = BuildCounter().Name("dns_total").Help("Total DNS").Register(*registry);
auto& dns_success = BuildCounter().Name("dns_success").Help("Successful DNS").Register(*registry);
auto& dns_failed = BuildGauge().Name("dns_failed").Help("Failed DNS").Register(*registry);

auto& http_total = BuildCounter().Name("http_total").Help("Total HTTP").Register(*registry);
auto& http_success = BuildCounter().Name("http_success").Help("Successful HTTP").Register(*registry);
auto& http_failed = BuildGauge().Name("http_failed").Help("Failed HTTP").Register(*registry);

auto& sip_total = BuildCounter().Name("sip_total").Help("Total SIP").Register(*registry);
auto& sip_success = BuildCounter().Name("sip_success").Help("Successful SIP").Register(*registry);
auto& sip_failed = BuildGauge().Name("sip_failed").Help("Failed SIP").Register(*registry);

auto& packets_received = BuildCounter().Name("packets_received").Help("Total packets received").Register(*registry);

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

template<typename T>
class SafeQueue {
    queue<T> q;
    mutable mutex m;
    condition_variable cv;
    atomic<bool> shutdown_{false}; 

public:
    void push(T&& val) {
        if (shutdown_) return;  // no accept for new items after shutdown
    
        lock_guard<mutex> lock(m);
        q.push(std::move(val));
        
        cv.notify_one();
    }

    bool pop(T& val) {
        unique_lock<mutex> lock(m);
        cv.wait(lock, [this]{ return !q.empty() || shutdown_; });
        if (shutdown_ && q.empty()) return false;
        val = std::move(q.front());
        q.pop();
        return true;
    }

    bool try_pop(T& val) {
        lock_guard<mutex> lock(m);
        if (q.empty() || shutdown_) return false; 
        val = std::move(q.front());
        q.pop();
        return true;
    }

    bool empty(){
        lock_guard<mutex> lock(m);
        return q.empty();
    }

    void shutdown() {  
        shutdown_ = true;
        cv.notify_all();  // wake all waiting threads up
    }
};

bool isValidPacket(const Binary& bin) {
    return bin.data != nullptr && 
           bin.length >= 14 && // eth
           bin.length <= 10000; // avoid spam
}

int main(int argc, char* argv[])
{
    sharedrep.dnsreport = &dnsrep;
    sharedrep.httpreport = &httprep;
    sharedrep.sipreport = &siprep;

    Exposer exposer{"0.0.0.0:8080"};
    exposer.RegisterCollectable(registry);

    int reportBuff = 10; // update every 10 packets for default
    if (argc > 1)
        reportBuff = stoi(argv[1]);

    string interface = "samples/htmldns.pcapng"; // default interface
    if (argc > 2)
        interface = argv[2];


    const int NUM_ANALYZERS = 2; // number of analyzer threads
    // multiple threads cant work on same source of packets, hardware limits!?
    // if true -> read from file ; if false read from interface 
    vector<pair<bool,string>> capture_interface = {{false,"wlp0s20f3"}};
    // other expamle :: vector<pair<bool,string>> capture_interface = {{true,"sample/htmldns.pcapng"}};
    SafeQueue<Binary> captureQ;
    vector<SafeQueue<Binary>> analyzerQs(NUM_ANALYZERS);
    atomic<bool> running = true;

    // -------- Capture Threads --------
    atomic<int> active_capturers{static_cast<int>(capture_interface.size())}; 

    vector<thread> capturers;
    for(int i = 0; i < capture_interface.size() ; i ++) {
        capturers.emplace_back([&, i]{
            PacketCapture cap;
            if(capture_interface[i].first == true){
                if (!cap.openFile(capture_interface[i].second)) {
                    cerr << "Failed to open interface " << capture_interface[i].second << endl;
                    active_capturers--; 
                    return false;
                }
            }
            if(capture_interface[i].first == false){
                if (!cap.openInterface(capture_interface[i].second)) {
                    cerr << "Failed to open interface " << capture_interface[i].second << endl;
                    active_capturers--;  
                    return false;
                }
            }
            
            Binary bin;
            while (cap.getNextPacket(bin)) 
                captureQ.push(std::move(bin));
            
            
            cap.close();
            active_capturers--;  // weve done with this interface
            
            if (active_capturers.load() == 0) 
            {
                running = false;
            }
            
            return true;
        }); 
    }

    // -------- TOQSER(مُقَسّم) Thread --------
    thread dispatcherThread([&] {
        Binary bin;
        while (running || !captureQ.empty()) {
            if (!captureQ.try_pop(bin)) {
                this_thread::sleep_for(1ms); // avoid busy spin
                continue;
            }
            size_t h = PacketUtils::flowHash(bin);
            analyzerQs[h % NUM_ANALYZERS].push(std::move(bin));
        }
    });

    // -------- Analyzer Threads --------
    vector<thread> analyzers;
    for (int i = 0; i < NUM_ANALYZERS; ++ i) {
        analyzers.emplace_back([&, i] {
            Reporter reporter(sharedrep);
            Binary bin;
            
            while (running) {
                if (analyzerQs[i].try_pop(bin)) {
                    if (isValidPacket(bin)) {
                        reporter.addBinary(bin);
                    }
                    delete[] bin.data; // avoid copy and more memory usage
                    bin.data = nullptr;
                } else {
                    // sleep to prevent busy-waiting
                    this_thread::sleep_for(1ms);
                    
                    // (no more packets and shutdown signaled)
                    if (!running && analyzerQs[i].empty()) {
                        break;
                    }
                }
            }
            
            //remaining packets after shutdown signal
            while (analyzerQs[i].try_pop(bin)) {
                if (isValidPacket(bin)) {
                    reporter.addBinary(bin);
                }
                delete[] bin.data;
                bin.data = nullptr;
            }
        });
    }

    // -------- (main thread) --------
    //old values
    int dns_s = 0, dns_t = 0;
    int htt_s = 0, htt_t = 0;
    int sip_s = 0, sip_t = 0;
    int rec = 0;

    cout << "Starting packet capture..." << endl;
    while (running) {
        this_thread::sleep_for(chrono::seconds(2));

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

    cout << "Initiating shutdown..." << endl;
    
    //  Signal shutdown to all threads
    running = false;
    
    //  Shutdown all queues to wake up waiting threads
    captureQ.shutdown();
    for (auto& q : analyzerQs) {
        q.shutdown();
    }
    
    cout << "Waiting for capturers thread..." << endl;
    for (auto& t : capturers) {
        t.join();
    }
    
    cout << "Waiting for dispatcher thread..." << endl;
    dispatcherThread.join();
    
    cout << "Waiting for analyzer threads..." << endl;
    for (auto& t : analyzers) {
        t.join();
    }
        
    // Final report
    cout << "[FINAL] " << sharedrep.recieved.load() << " packets processed." << endl;
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
    
    cout << "Capture finished." << endl;
    return 0;
}