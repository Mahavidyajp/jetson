#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <thread>
#include <mutex>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <regex>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// Your generated MAVLink headers
extern "C" {
#include "/home/jetson/mavlink/generated/include/mavlink/v2.0/common/mavlink.h"
}


// ============================================================
// Configuration
// ============================================================

static const char *MAVLINK_HOST = "127.0.0.1";
static constexpr uint16_t MAVLINK_PORT = 14551;

// Jetson companion computer MAVLink identity
static constexpr uint8_t SYSTEM_ID = 1;
static constexpr uint8_t COMPONENT_ID = 191;

// ONBOARD_COMPUTER_STATUS type:
// 0 = Mission computer primary
// 3 = Compute node
static constexpr uint8_t COMPUTER_TYPE = 0;

// Send rate
static constexpr int SEND_INTERVAL_MS = 1000;

// MAVLink2 signing.
// The GCS runs strict signing: it accepts unsigned frames only for
// RADIO_STATUS, so unsigned HEARTBEAT / CELLULAR_STATUS /
// ONBOARD_COMPUTER_STATUS from this component are silently dropped.
// The key must match the one the GCS holds. It is read from a root-only
// file (64 hex characters, 32 bytes), never compiled into the binary.
static const char *SIGNING_KEY_PATH = "/etc/jetson-status/signing.key";
static constexpr uint8_t SIGNING_LINK_ID = 1;


// ============================================================
// Utility
// ============================================================

std::string run_command(const std::string &cmd)
{
    std::array<char, 512> buffer{};
    std::string result;

    FILE *pipe = popen(cmd.c_str(), "r");

    if (!pipe)
        return result;

    while (fgets(buffer.data(), buffer.size(), pipe))
        result += buffer.data();

    pclose(pipe);

    return result;
}


// ============================================================
// MAVLink signing setup
// ============================================================

mavlink_signing_t signing{};
bool signing_enabled = false;

// Loads a 64-character hex key into `key`. Never logs the key itself.
bool load_signing_key(const std::string &path, uint8_t key[32])
{
    std::ifstream file(path);

    if (!file)
        return false;

    std::string hex;
    file >> hex;

    if (hex.size() != 64)
    {
        std::cerr << "Signing key file must hold 64 hex characters\n";
        return false;
    }

    for (std::size_t i = 0; i < 32; ++i)
    {
        unsigned value = 0;

        if (std::sscanf(hex.c_str() + 2 * i, "%2x", &value) != 1)
        {
            std::cerr << "Signing key file contains non-hex data\n";
            return false;
        }

        key[i] = static_cast<uint8_t>(value);
    }

    return true;
}

// MAVLink2 timestamps are 10 us ticks since 2015-01-01 00:00:00 UTC.
// The receiver rejects timestamps that lag its own clock by more than
// 60 s, so this is refreshed from the wall clock before every send.
uint64_t signing_timestamp_now()
{
    constexpr uint64_t MAVLINK_EPOCH_UNIX_US = 1420070400ULL * 1000000ULL;

    uint64_t unix_us =
        static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::system_clock::now()
                    .time_since_epoch())
                .count());

    return (unix_us - MAVLINK_EPOCH_UNIX_US) / 10;
}


// ============================================================
// MAVLink UDP output
// ============================================================

int mavlink_socket = -1;
struct sockaddr_in mavlink_addr{};

bool open_mavlink_udp()
{
    mavlink_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (mavlink_socket < 0)
    {
        perror("socket");
        return false;
    }

    mavlink_addr.sin_family = AF_INET;
    mavlink_addr.sin_port = htons(MAVLINK_PORT);

    if (inet_pton(AF_INET, MAVLINK_HOST, &mavlink_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid MAVLink UDP address\n";
        close(mavlink_socket);
        mavlink_socket = -1;
        return false;
    }

    return true;
}

void send_mavlink(mavlink_message_t &message)
{
    if (mavlink_socket < 0)
        return;

    uint8_t buffer[MAVLINK_MAX_PACKET_LEN];
    uint16_t len = mavlink_msg_to_send_buffer(buffer, &message);

    ssize_t written = sendto(
        mavlink_socket,
        buffer,
        len,
        0,
        reinterpret_cast<const struct sockaddr *>(&mavlink_addr),
        sizeof(mavlink_addr));

    if (written != static_cast<ssize_t>(len))
    {
        std::cerr << "Warning: UDP send incomplete: "
                  << written << "/" << len << std::endl;
    }
}


// ============================================================
// CPU
// ============================================================

struct CpuTimes
{
    uint64_t idle = 0;
    uint64_t total = 0;
};


std::vector<CpuTimes> read_cpu_times()
{
    std::ifstream file("/proc/stat");

    std::vector<CpuTimes> result;

    std::string line;

    while (std::getline(file, line))
    {
        if (line.rfind("cpu", 0) != 0)
            break;

        if (line.size() < 4)
            continue;

        // cpu0, cpu1, ...
        if (!isdigit(line[3]))
            continue;

        std::istringstream iss(line);

        std::string cpu;

        uint64_t user = 0;
        uint64_t nice = 0;
        uint64_t system = 0;
        uint64_t idle = 0;
        uint64_t iowait = 0;
        uint64_t irq = 0;
        uint64_t softirq = 0;
        uint64_t steal = 0;

        iss >> cpu
            >> user
            >> nice
            >> system
            >> idle
            >> iowait
            >> irq
            >> softirq
            >> steal;

        uint64_t idle_total = idle + iowait;

        uint64_t total =
            user + nice + system +
            idle + iowait +
            irq + softirq + steal;

        result.push_back({idle_total, total});
    }

    return result;
}


uint8_t cpu_usage(const CpuTimes &old,
                  const CpuTimes &now)
{
    uint64_t total_delta = now.total - old.total;
    uint64_t idle_delta = now.idle - old.idle;

    if (total_delta == 0)
        return 0;

    double usage =
        100.0 *
        (1.0 - static_cast<double>(idle_delta) /
                static_cast<double>(total_delta));

    usage = std::clamp(usage, 0.0, 100.0);

    return static_cast<uint8_t>(usage);
}


// ============================================================
// RAM
// ============================================================

void read_ram(uint32_t &used_mib,
              uint32_t &total_mib)
{
    std::ifstream file("/proc/meminfo");

    uint64_t total_kb = 0;
    uint64_t available_kb = 0;

    std::string key;
    uint64_t value;
    std::string unit;

    while (file >> key >> value >> unit)
    {
        if (key == "MemTotal:")
            total_kb = value;

        else if (key == "MemAvailable:")
            available_kb = value;
    }

    total_mib = total_kb / 1024;

    uint64_t used_kb =
        (total_kb > available_kb)
        ? total_kb - available_kb
        : 0;

    used_mib = used_kb / 1024;
}


// ============================================================
// Temperature
// ============================================================

int8_t read_temperature()
{
    int best_temp = -1000;

    for (int i = 0; i < 30; ++i)
    {
        std::string path =
            "/sys/class/thermal/thermal_zone" +
            std::to_string(i) +
            "/temp";

        std::ifstream file(path);

        if (!file)
            continue;

        long temp;

        if (file >> temp)
        {
            int celsius = static_cast<int>(temp / 1000);

            best_temp = std::max(best_temp, celsius);
        }
    }

    if (best_temp < -100)
        return INT8_MAX;

    best_temp = std::clamp(best_temp, -127, 127);

    return static_cast<int8_t>(best_temp);
}


// ============================================================
// Storage
// ============================================================

void read_storage(uint32_t &used_mib,
                  uint32_t &total_mib)
{
    struct statvfs stat{};

    if (statvfs("/", &stat) != 0)
    {
        used_mib = UINT32_MAX;
        total_mib = UINT32_MAX;
        return;
    }

    uint64_t total =
        static_cast<uint64_t>(stat.f_blocks) *
        stat.f_frsize;

    uint64_t free =
        static_cast<uint64_t>(stat.f_bavail) *
        stat.f_frsize;

    uint64_t used = total - free;

    used_mib = used / (1024 * 1024);
    total_mib = total / (1024 * 1024);
}


// ============================================================
// Network
// ============================================================

struct NetStats
{
    uint64_t rx = 0;
    uint64_t tx = 0;
};


NetStats read_network(const std::string &interface)
{
    std::ifstream file("/proc/net/dev");

    std::string line;

    while (std::getline(file, line))
    {
        if (line.find(interface + ":") == std::string::npos)
            continue;

        auto colon = line.find(':');

        std::string data =
            line.substr(colon + 1);

        std::istringstream iss(data);

        NetStats stats;

        uint64_t rx_packets;
        uint64_t rx_errors;
        uint64_t rx_drop;
        uint64_t rx_fifo;
        uint64_t rx_frame;
        uint64_t rx_compressed;
        uint64_t rx_multicast;

        uint64_t tx_packets;
        uint64_t tx_errors;
        uint64_t tx_drop;
        uint64_t tx_fifo;
        uint64_t tx_collisions;
        uint64_t tx_carrier;
        uint64_t tx_compressed;

        iss >>
            stats.rx >>
            rx_packets >>
            rx_errors >>
            rx_drop >>
            rx_fifo >>
            rx_frame >>
            rx_compressed >>
            rx_multicast >>
            tx_packets >>
            tx_errors >>
            tx_drop >>
            tx_fifo >>
            tx_collisions >>
            tx_carrier >>
            tx_compressed;

        stats.tx = tx_packets;

        // The above assignment is corrected below by reading
        // the actual byte counters again.
        std::istringstream iss2(data);

        iss2 >>
            stats.rx >>
            rx_packets >>
            rx_errors >>
            rx_drop >>
            rx_fifo >>
            rx_frame >>
            rx_compressed >>
            rx_multicast >>
            stats.tx;

        return stats;
    }

    return {};
}


// Simpler network reader.
// /proc/net/dev format:
// RX bytes ... TX bytes ...
NetStats read_network_bytes(const std::string &interface)
{
    std::ifstream file("/proc/net/dev");

    std::string line;

    while (std::getline(file, line))
    {
        auto colon = line.find(':');

        if (colon == std::string::npos)
            continue;

        std::string name = line.substr(0, colon);

        name.erase(
            std::remove_if(
                name.begin(),
                name.end(),
                [](unsigned char c)
                {
                    return std::isspace(c);
                }),
            name.end());

        if (name != interface)
            continue;

        std::istringstream iss(
            line.substr(colon + 1));

        NetStats stats;

        uint64_t rx_packets;
        uint64_t rx_err;
        uint64_t rx_drop;
        uint64_t rx_fifo;
        uint64_t rx_frame;
        uint64_t rx_compressed;
        uint64_t rx_multicast;

        uint64_t tx_packets;
        uint64_t tx_err;
        uint64_t tx_drop;
        uint64_t tx_fifo;
        uint64_t tx_collisions;
        uint64_t tx_carrier;
        uint64_t tx_compressed;

        iss >>
            stats.rx >>
            rx_packets >>
            rx_err >>
            rx_drop >>
            rx_fifo >>
            rx_frame >>
            rx_compressed >>
            rx_multicast >>
            stats.tx >>
            tx_packets >>
            tx_err >>
            tx_drop >>
            tx_fifo >>
            tx_collisions >>
            tx_carrier >>
            tx_compressed;

        return stats;
    }

    return {};
}


// ============================================================
// ModemManager cellular status
// ============================================================

struct CellularInfo
{
    uint8_t status = 0;
    uint8_t failure_reason = 0;

    uint8_t type = 4;       // LTE

    uint8_t quality = UINT8_MAX;

    uint16_t mcc = UINT16_MAX;
    uint16_t mnc = UINT16_MAX;
    uint16_t lac = 0;

    uint8_t id = 0;

    uint32_t tx_rate = UINT32_MAX;
    uint32_t rx_rate = UINT32_MAX;

    std::string tower;

    uint8_t band_number = 0;
    float band_frequency = 0.0f;

    uint32_t channel_number = 0;

    float rx_level = NAN;
    float tx_level = NAN;
    float rx_quality = NAN;
    float sinr = NAN;
};


bool extract_number_after(
    const std::string &text,
    const std::string &key,
    int &value)
{
    size_t pos = text.find(key);

    if (pos == std::string::npos)
        return false;

    pos += key.size();

    while (pos < text.size() &&
           (text[pos] == ' ' ||
            text[pos] == ':' ||
            text[pos] == '('))
    {
        pos++;
    }

    try
    {
        value = std::stoi(text.substr(pos));
        return true;
    }
    catch (...)
    {
        return false;
    }
}


// Extract an integer after a textual key.
bool extract_int(const std::string &text,
                 const std::string &key,
                 int &value)
{
    size_t pos = text.find(key);

    if (pos == std::string::npos)
        return false;

    pos += key.size();

    while (pos < text.size() &&
           (text[pos] == ' ' ||
            text[pos] == ':' ||
            text[pos] == '(' ||
            text[pos] == '='))
    {
        ++pos;
    }

    try
    {
        value = std::stoi(text.substr(pos));
        return true;
    }
    catch (...)
    {
        return false;
    }
}


// Run an AT command against a Quectel/SIMCom-style USB AT port.
// ttyUSB2/ttyUSB3 are the ports that were confirmed to answer AT on this Jetson.
std::string run_at_command(const std::string &port,
                           const std::string &command)
{
    std::string shell =
        "bash -c '{ "
        "stty -F " + port + " 115200 cs8 -cstopb -parenb raw -echo; "
        "printf \"" + command + "\\r\" > " + port + "; "
        "timeout 2 cat " + port +
        "; } 2>/dev/null'";

    return run_command(shell);
}


std::string read_modem_at()
{
    // Prefer the ports already confirmed to respond to AT.
    const char *ports[] = {
        "/dev/ttyUSB2",
        "/dev/ttyUSB3"
    };

    for (const char *port : ports)
    {
        std::string qeng =
            run_at_command(port, "AT+QENG=\"servingcell\"");

        if (qeng.find("+QENG:") != std::string::npos)
            return qeng;

        std::string csq =
            run_at_command(port, "AT+CSQ");

        if (csq.find("+CSQ:") != std::string::npos)
            return csq;
    }

    return {};
}


// Convert CSQ (0..31) into the percentage expected by CELLULAR_STATUS.
// CSQ 99 means unknown.
uint8_t csq_to_percent(int csq)
{
    if (csq < 0 || csq > 31)
        return UINT8_MAX;

    return static_cast<uint8_t>(
        std::lround((static_cast<double>(csq) / 31.0) * 100.0));
}


// Convert RSRP in dBm to a rough 0..100 quality value.
// This is only used when CSQ is unavailable.
uint8_t rsrp_to_percent(float rsrp)
{
    if (!std::isfinite(rsrp))
        return UINT8_MAX;

    // Rough engineering range:
    // -120 dBm = 0%, -80 dBm = 100%.
    double p =
        (static_cast<double>(rsrp) + 120.0) * 2.5;

    p = std::clamp(p, 0.0, 100.0);

    return static_cast<uint8_t>(std::lround(p));
}


CellularInfo read_cellular()
{
    CellularInfo c;

    // --------------------------------------------------------
    // 1. Try ModemManager first.
    // --------------------------------------------------------

    std::string mm =
        run_command("mmcli -m 0 2>/dev/null");

    if (!mm.empty())
    {
        if (mm.find("packet service state: attached") !=
            std::string::npos)
        {
            c.status = 9; // registered
        }

        if (mm.find("state: registered") !=
            std::string::npos)
        {
            c.status = 9;
        }

        if (mm.find("state: connected") !=
            std::string::npos)
        {
            c.status = 12; // connected
        }

        if (mm.find("state: searching") !=
            std::string::npos)
        {
            c.status = 8; // searching
        }

        // Signal quality: "signal quality: 51% (recent)"
        size_t pos = mm.find("signal quality:");

        if (pos != std::string::npos)
        {
            pos += strlen("signal quality:");

            try
            {
                int q = std::stoi(mm.substr(pos));

                if (q >= 0 && q <= 100)
                    c.quality = static_cast<uint8_t>(q);
            }
            catch (...)
            {
            }
        }

        // Operator ID: "operator id: 40440"
        int operator_id = 0;

        if (extract_int(mm, "operator id:", operator_id) &&
            operator_id >= 10000 &&
            operator_id <= 999999)
        {
            c.mcc =
                static_cast<uint16_t>(operator_id / 100);

            c.mnc =
                static_cast<uint16_t>(operator_id % 100);
        }
    }

    // --------------------------------------------------------
    // 2. Always use the modem AT interface as a fallback and
    //    as the authoritative source for 5G serving-cell data.
    //
    // Your modem reported:
    // +CNSMOD: 1,36
    // +QENG:"servingcell","CONNECT","NR5G-SA","TDD",
    //        404,40,13322983735,642,0xA4B8,629952,
    //        NR5G_BAND78,14,-985,-135,4,1,0
    //
    // Therefore we can get:
    //   technology = NR5G-SA
    //   MCC        = 404
    //   MNC        = 40
    //   band       = 78
    //   channel    = 629952
    //   RSRP       = -98.5 dBm
    //   RSRQ       = -13.5 dB
    //   SINR       = 4 dB
    // --------------------------------------------------------

    std::string at =
        read_modem_at();

    if (!at.empty())
    {
        // +CSQ: 15,99
        size_t csq_pos = at.find("+CSQ:");

        if (csq_pos != std::string::npos)
        {
            int csq = -1;

            try
            {
                csq =
                    std::stoi(
                        at.substr(csq_pos + 5));
            }
            catch (...)
            {
            }

            uint8_t q = csq_to_percent(csq);

            if (q != UINT8_MAX)
                c.quality = q;
        }

        // +CNSMOD: 1,36
        // 36 = 5G SA on this modem.
        bool is_5g = false;

        size_t cns_pos = at.find("+CNSMOD:");

        if (cns_pos != std::string::npos)
        {
            std::string line =
                at.substr(cns_pos, at.find('\n', cns_pos) - cns_pos);

            if (line.find(",36") != std::string::npos ||
                line.find(",37") != std::string::npos)
            {
                is_5g = true;
            }
        }

        // QENG serving-cell response.
        size_t qeng_pos = at.find("+QENG:");

        if (qeng_pos != std::string::npos)
        {
            std::string line =
                at.substr(
                    qeng_pos,
                    at.find('\n', qeng_pos) == std::string::npos
                        ? std::string::npos
                        : at.find('\n', qeng_pos) - qeng_pos);

            // Remove CR.
            line.erase(
                std::remove(line.begin(), line.end(), '\r'),
                line.end());

            // Detect NR5G-SA / NR5G-NSA.
            if (line.find("NR5G-SA") != std::string::npos ||
                line.find("NR5G-NSA") != std::string::npos)
            {
                is_5g = true;
            }

            // Parse:
            // +QENG:"servingcell","CONNECT","NR5G-SA","TDD",
            // 404,40,13322983735,642,0xA4B8,629952,
            // NR5G_BAND78,14,-985,-135,4,1,0

            std::regex nr_regex(
                R"(NR5G_BAND([0-9]+),([0-9]+),(-?[0-9]+),(-?[0-9]+),(-?[0-9]+))");

            std::smatch match;

            if (std::regex_search(line, match, nr_regex))
            {
                try
                {
                    // NR band number.
                    c.band_number =
                        static_cast<uint8_t>(
                            std::stoi(match[1].str()));

                    // Bandwidth/index field from QENG.
                    // Not directly represented in CELLULAR_STATUS,
                    // so do not put it into band_frequency.

                    // RSRP is reported by this modem in tenths of dBm.
                    c.rx_level =
                        static_cast<float>(
                            std::stoi(match[3].str()) / 10.0);

                    // RSRQ in dB.
                    c.rx_quality =
                        static_cast<float>(
                            std::stoi(match[4].str()) / 10.0);

                    // SINR in dB.
                    c.sinr =
                        static_cast<float>(
                            std::stoi(match[5].str()));

                    // Use RSRP when CSQ was unavailable.
                    if (c.quality == UINT8_MAX)
                        c.quality =
                            rsrp_to_percent(c.rx_level);
                }
                catch (...)
                {
                }
            }

            // Parse MCC/MNC from the serving-cell line.
            // For NR5G-SA:
            // "NR5G-SA","TDD",404,40,...
            std::regex mcc_mnc_regex(
                R"re(NR5G-(?:SA|NSA)","[^"]+",([0-9]{3}),([0-9]{2,3}),)re");

            if (std::regex_search(line, match, mcc_mnc_regex))
            {
                try
                {
                    c.mcc =
                        static_cast<uint16_t>(
                            std::stoi(match[1].str()));

                    c.mnc =
                        static_cast<uint16_t>(
                            std::stoi(match[2].str()));
                }
                catch (...)
                {
                }
            }

            // Channel / NR-ARFCN:
            // after cell id, PCI, band-id, etc. the QENG line
            // contains 629952 in your example.
            std::regex arfcn_regex(
                R"(0x[0-9A-Fa-f]+,([0-9]+),NR5G_BAND)");

            if (std::regex_search(line, match, arfcn_regex))
            {
                try
                {
                    c.channel_number =
                        static_cast<uint32_t>(
                            std::stoul(match[1].str()));
                }
                catch (...)
                {
                }
            }
        }

        if (is_5g)
        {
            // IMPORTANT:
            // Standard MAVLink CELLULAR_NETWORK_RADIO_TYPE currently
            // has no 5G value. We therefore keep type=4 (LTE) for
            // protocol compatibility, while exposing the real 5G
            // information through band_number/channel_number/
            // rx_level/rx_quality/sinr.
            //
            // QGC can use NR5G_BANDxx or the serving-cell data to
            // display "5G" in a custom cellular indicator.
            c.type = 4;

            // If AT proves the modem is registered on 5G, make sure
            // the status is not left at zero just because ModemManager
            // failed to create a modem after USB reconnect.
            if (c.status == 0)
                c.status = 9;
        }
    }

    // --------------------------------------------------------
    // 3. Final fallback: if the modem is physically present but
    //    neither MM nor AT returned useful state, leave unknown.
    // --------------------------------------------------------

    c.id = 0;

    return c;
}

// ============================================================
// Background cellular polling
//
// read_cellular() always shells out to blocking AT commands
// (timeout 2 cat /dev/ttyUSB2, up to ~8s worst case across both
// ports) to get 5G serving-cell detail that ModemManager's D-Bus
// API doesn't expose for this modem. Calling it inline from the
// main loop stretched the 1 Hz MAVLink send cadence out to ~9s,
// so HEARTBEAT/ONBOARD_COMPUTER_STATUS/CELLULAR_STATUS for this
// component arrived far too slowly for GCS tools to keep it live
// in the MAVLink Inspector. Poll it on its own thread instead and
// have the send loop always use the latest cached reading.
// ============================================================

std::mutex cellular_mutex;
CellularInfo cached_cellular;

void cellular_poll_thread()
{
    while (true)
    {
        CellularInfo c = read_cellular();

        {
            std::lock_guard<std::mutex> lock(cellular_mutex);
            cached_cellular = c;
        }

        // read_cellular() already blocks for most of this; this is
        // just a floor so a surprisingly-fast AT response can't spin.
        std::this_thread::sleep_for(
            std::chrono::milliseconds(200));
    }
}

CellularInfo latest_cellular()
{
    std::lock_guard<std::mutex> lock(cellular_mutex);
    return cached_cellular;
}

// ============================================================
// Send ONBOARD_COMPUTER_STATUS #390
// ============================================================

void send_onboard_status(
    const std::vector<CpuTimes> &previous_cpu,
    const std::vector<CpuTimes> &current_cpu,
    uint32_t ram_used,
    uint32_t ram_total,
    int8_t board_temp,
    uint32_t storage_used,
    uint32_t storage_total,
    uint32_t tx_rate,
    uint32_t rx_rate)
{
    uint8_t cpu_cores[8];

    for (int i = 0; i < 8; ++i)
        cpu_cores[i] = UINT8_MAX;

    int cpu_count =
        std::min(
            static_cast<int>(current_cpu.size()),
            8);

    for (int i = 0; i < cpu_count; ++i)
    {
        cpu_cores[i] =
            cpu_usage(
                previous_cpu[i],
                current_cpu[i]);
    }

    // GPU not implemented yet.
    uint8_t gpu_cores[4];

    for (auto &v : gpu_cores)
        v = UINT8_MAX;

    uint8_t cpu_combined[10];

    // Histogram field: use recent CPU total, aggregated across all cores
    // (current_cpu[0]/previous_cpu[0] is core 0 only — read_cpu_times()
    // skips the /proc/stat summary line — so it cannot stand in for the
    // system-wide figure this field is meant to report).
    // More sophisticated 100 ms history can be added later.
    uint8_t total_cpu = 0;

    if (!current_cpu.empty() &&
        current_cpu.size() == previous_cpu.size())
    {
        uint64_t idle_delta = 0;
        uint64_t total_delta = 0;

        for (std::size_t i = 0; i < current_cpu.size(); ++i)
        {
            idle_delta +=
                current_cpu[i].idle -
                previous_cpu[i].idle;

            total_delta +=
                current_cpu[i].total -
                previous_cpu[i].total;
        }

        if (total_delta > 0)
        {
            double usage =
                100.0 *
                (1.0 -
                 static_cast<double>(idle_delta) /
                 static_cast<double>(total_delta));

            total_cpu =
                static_cast<uint8_t>(
                    std::clamp(usage, 0.0, 100.0));
        }
    }

    for (auto &v : cpu_combined)
        v = total_cpu;

    uint8_t gpu_combined[10];

    for (auto &v : gpu_combined)
        v = UINT8_MAX;

    int8_t temperature_core[8];

    for (auto &v : temperature_core)
        v = INT8_MAX;

    int16_t fan_speed[4];

    for (auto &v : fan_speed)
        v = INT16_MAX;

    uint32_t storage_type[4];

    for (auto &v : storage_type)
        v = UINT32_MAX;

    uint32_t storage_usage[4];

    for (auto &v : storage_usage)
        v = UINT32_MAX;

    uint32_t storage_total_array[4];

    for (auto &v : storage_total_array)
        v = UINT32_MAX;

    // Root filesystem = SSD/NVMe/other block storage.
    // We use STORAGE type 0 (HDD) only as a generic placeholder
    // because this field's storage type is limited to the values
    // defined by ONBOARD_COMPUTER_STATUS.
    storage_type[0] = 0;
    storage_usage[0] = storage_used;
    storage_total_array[0] = storage_total;

    uint32_t link_type[6];

    uint32_t link_tx_rate[6];
    uint32_t link_rx_rate[6];
    uint32_t link_tx_max[6];
    uint32_t link_rx_max[6];

    for (int i = 0; i < 6; ++i)
    {
        link_type[i] = 0;
        link_tx_rate[i] = UINT32_MAX;
        link_rx_rate[i] = UINT32_MAX;
        link_tx_max[i] = UINT32_MAX;
        link_rx_max[i] = UINT32_MAX;
    }

    // usb0 = SIM8262E-M2 RNDIS interface.
    // Link type 10-19 = wired network.
    link_type[0] = 10;

    link_tx_rate[0] = tx_rate;
    link_rx_rate[0] = rx_rate;

    // No reliable interface capacity information.
    link_tx_max[0] = UINT32_MAX;
    link_rx_max[0] = UINT32_MAX;

    uint16_t status_flags = 0;

    // Disk full if >95%.
    if (storage_total > 0)
    {
        double usage =
            100.0 *
            static_cast<double>(storage_used) /
            static_cast<double>(storage_total);

        if (usage >= 95.0)
            status_flags |= 8;
    }

    uint64_t uptime_ms = 0;

    {
        std::ifstream file("/proc/uptime");

        double seconds = 0;

        if (file >> seconds)
            uptime_ms =
                static_cast<uint64_t>(
                    seconds * 1000.0);
    }

    uint64_t time_usec =
        static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::system_clock::now()
                    .time_since_epoch())
                .count());

    mavlink_message_t msg;

    mavlink_msg_onboard_computer_status_pack(
        SYSTEM_ID,
        COMPONENT_ID,
        &msg,

        time_usec,
        static_cast<uint32_t>(uptime_ms),

        COMPUTER_TYPE,

        cpu_cores,
        cpu_combined,

        gpu_cores,
        gpu_combined,

        board_temp,

        temperature_core,
        fan_speed,

        ram_used,
        ram_total,

        storage_type,
        storage_usage,
        storage_total_array,

        link_type,
        link_tx_rate,
        link_rx_rate,

        link_tx_max,
        link_rx_max,

        status_flags);

    send_mavlink(msg);
}


// ============================================================
// Send CELLULAR_STATUS #334
// ============================================================

void send_cellular_status(
    const CellularInfo &c,
    uint32_t tx_rate,
    uint32_t rx_rate)
{
    mavlink_message_t msg;

    mavlink_msg_cellular_status_pack(
        SYSTEM_ID,
        COMPONENT_ID,
        &msg,

        c.status,
        c.failure_reason,
        c.type,
        c.quality,

        c.mcc,
        c.mnc,
        c.lac,

        c.id,

        tx_rate,
        rx_rate,

        c.tower.c_str(),

        c.band_number,
        c.band_frequency,

        c.channel_number,

        c.rx_level,
        c.tx_level,

        c.rx_quality,
        c.sinr);

    send_mavlink(msg);
}


// ============================================================
// Send HEARTBEAT #0
//
// Announces this component (sysid 1 / compid 191) on the bus so GCS
// apps that discover components via HEARTBEAT (e.g. QGroundControl's
// MAVLink Inspector) register it as a selectable source.
// ============================================================

void send_heartbeat()
{
    mavlink_message_t msg;

    mavlink_msg_heartbeat_pack(
        SYSTEM_ID,
        COMPONENT_ID,
        &msg,

        MAV_TYPE_ONBOARD_CONTROLLER,
        MAV_AUTOPILOT_INVALID,
        0,
        0,
        MAV_STATE_ACTIVE);

    send_mavlink(msg);
}


// ============================================================
// Main
// ============================================================

int main()
{
    std::cout
        << "============================================\n"
        << " Jetson MAVLink Computer + Cellular Status\n"
        << "============================================\n";

    std::cout
        << "MAVLink output: UDP "
        << MAVLINK_HOST << ":" << MAVLINK_PORT << "\n"
        << "System ID: " << static_cast<int>(SYSTEM_ID) << "\n"
        << "Component ID: " << static_cast<int>(COMPONENT_ID) << "\n\n";

    if (!open_mavlink_udp())
    {
        std::cerr << "Could not open MAVLink UDP socket\n";
        return 1;
    }

    // The pack functions below finalize on MAVLINK_COMM_0. Attaching the
    // signing state to that channel makes them sign every frame they build.
    if (load_signing_key(SIGNING_KEY_PATH, signing.secret_key))
    {
        signing.link_id = SIGNING_LINK_ID;
        signing.flags = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;

        mavlink_get_channel_status(MAVLINK_COMM_0)->signing = &signing;
        signing_enabled = true;

        std::cout << "MAVLink signing enabled (link "
                  << static_cast<int>(SIGNING_LINK_ID) << ")\n";
    }
    else
    {
        std::cerr
            << "Warning: no signing key at " << SIGNING_KEY_PATH
            << "; sending UNSIGNED frames, which the GCS will drop\n";
    }

    std::cout
        << "MAVLink UDP connected to mavlink-router.\n"
        << "Starting telemetry...\n\n";

    auto previous_cpu =
        read_cpu_times();

    auto previous_net =
        read_network_bytes("usb0");

    std::thread(cellular_poll_thread).detach();

    std::this_thread::sleep_for(
        std::chrono::milliseconds(1000));

    while (true)
    {
        try
        {
            if (signing_enabled)
                signing.timestamp = signing_timestamp_now();

            auto current_cpu =
                read_cpu_times();

            // ------------------------------------------------
            // CPU
            // ------------------------------------------------

            uint8_t total_cpu = 0;

            if (!current_cpu.empty() &&
                !previous_cpu.empty())
            {
                total_cpu =
                    cpu_usage(
                        previous_cpu[0],
                        current_cpu[0]);
            }

            // ------------------------------------------------
            // RAM
            // ------------------------------------------------

            uint32_t ram_used;
            uint32_t ram_total;

            read_ram(
                ram_used,
                ram_total);

            // ------------------------------------------------
            // Temperature
            // ------------------------------------------------

            int8_t temperature =
                read_temperature();

            // ------------------------------------------------
            // Storage
            // ------------------------------------------------

            uint32_t storage_used;
            uint32_t storage_total;

            read_storage(
                storage_used,
                storage_total);

            // ------------------------------------------------
            // USB0 / 5G RNDIS traffic
            // ------------------------------------------------

            auto current_net =
                read_network_bytes("usb0");

            uint32_t tx_rate = 0;
            uint32_t rx_rate = 0;

            if (current_net.tx >= previous_net.tx)
            {
                tx_rate =
                    static_cast<uint32_t>(
                        (current_net.tx -
                         previous_net.tx) /
                        1024);
            }

            if (current_net.rx >= previous_net.rx)
            {
                rx_rate =
                    static_cast<uint32_t>(
                        (current_net.rx -
                         previous_net.rx) /
                        1024);
            }

            // ------------------------------------------------
            // Cellular
            // ------------------------------------------------

            CellularInfo cellular =
                latest_cellular();

            // ------------------------------------------------
            // Send #0 (component heartbeat)
            // ------------------------------------------------

            send_heartbeat();

            // ------------------------------------------------
            // Send #390
            // ------------------------------------------------

            send_onboard_status(

                previous_cpu,
                current_cpu,

                ram_used,
                ram_total,

                temperature,

                storage_used,
                storage_total,

                tx_rate,
                rx_rate);

            // ------------------------------------------------
            // Send #334
            // ------------------------------------------------

            send_cellular_status(
                cellular,
                tx_rate,
                rx_rate);

            // ------------------------------------------------
            // Console
            // ------------------------------------------------

            std::cout
                << "CPU "
                << static_cast<int>(total_cpu)
                << "% | RAM "
                << ram_used
                << "/"
                << ram_total
                << " MiB"
                << " | Temp "
                << static_cast<int>(temperature)
                << " C"
                << " | 5G signal "
                << (cellular.quality == UINT8_MAX
                    ? -1
                    : static_cast<int>(cellular.quality))
                << "%"
                << " | MCC "
                << (cellular.mcc == UINT16_MAX
                    ? 0
                    : cellular.mcc)
                << " MNC "
                << (cellular.mnc == UINT16_MAX
                    ? 0
                    : cellular.mnc)
                << " | TX "
                << tx_rate
                << " KiB/s"
                << " RX "
                << rx_rate
                << " KiB/s"
                << " | CELL_STATUS "
                << static_cast<int>(cellular.status)
                << "\n";

            previous_cpu = current_cpu;
            previous_net = current_net;

            std::this_thread::sleep_for(
                std::chrono::milliseconds(
                    SEND_INTERVAL_MS));
        }
        catch (const std::exception &e)
        {
            std::cerr
                << "Exception: "
                << e.what()
                << "\n";

            std::this_thread::sleep_for(
                std::chrono::seconds(1));
        }
    }

    close(mavlink_socket);

    return 0;
}
