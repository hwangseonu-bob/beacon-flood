#include <iostream>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <ctime>
#include <cstring>
#include <unistd.h>

#define MAX_PACKET_SIZE 8192

using namespace std;

using Hwaddr = uint8_t[6];

struct RadioTap {
    uint8_t revision;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
} __attribute__((__packed__));

struct BeaconFrame {
    uint16_t frame_control;
    uint16_t duration;
    Hwaddr dmac;
    Hwaddr smac;
    Hwaddr bssid;
    uint16_t seq;
} __attribute__((__packed__));

struct WirelessManagement {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
    uint8_t tag_num;
    uint8_t tag_len;
    u_char ssid[255];
} __attribute__((__packed__));

struct BeaconFramePacket {
    RadioTap radioTap;
    BeaconFrame beaconFrame;
    WirelessManagement wirelessManagement;
} __attribute__((__packed__));

vector<string> readSsidList(char *filename) {
    ifstream ifs(filename);

    if (ifs.fail()) {
        cerr << "cannot open " << filename << endl;
        exit(1);
    }

    vector<string> result;
    string line;
    while (!ifs.eof()) {
        ifs >> line;
        result.emplace_back(line);
    }
    ifs.close();
    return result;
}

void usage(char *cmd) {
    cout << "syntax: " << cmd << " <interface> <ssid-list-file>" << endl;
    cout << "example: " << cmd << " wlan0 ssid-list.txt" << endl;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 1, 512, errbuf);

    if (handle == nullptr) {
        cerr << errbuf << endl;
        return -1;
    }

    vector<string> ssidList = readSsidList(argv[2]);

    while(true) {
        for (auto ssid : ssidList) {
            RadioTap radioTap{
                    0x00,
                    0x00,
                    0x0008,
                    0x00000000
            };

            BeaconFrame beaconFrame{
                    0x0080,
                    0,
                    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                    {0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
                    {0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
                    0
            };

            WirelessManagement wirelessManagement{
                    0,
                    0,
                    0,
                    0,
                    static_cast<uint8_t>(ssid.size()),
            };
            uint8_t supportedRates[] = {0x01, 0x03, 0x82, 0x8b, 0x96};

            ::memcpy(wirelessManagement.ssid, ssid.data(), ssid.size());
            ::memcpy(wirelessManagement.ssid + ssid.size(), supportedRates, 5);

            BeaconFramePacket packet{
                    radioTap,
                    beaconFrame,
                    wirelessManagement
            };
            int packet_size = sizeof(BeaconFramePacket) - 255 + ssid.size() + 5;

            int res = pcap_sendpacket(handle, reinterpret_cast<uint8_t *>(&packet), packet_size);

            if (res != 0) {
                cerr << pcap_geterr(handle) << endl;
                return -1;
            }

            usleep(10000);
        }
    }

    return 0;
}
