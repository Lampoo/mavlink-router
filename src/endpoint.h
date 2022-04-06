/*
 * This file is part of the MAVLink Router project
 *
 * Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <common/conf_file.h>
#include <common/mavlink.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstdarg>
#include <net/if.h>

#include "comm.h"
#include "pollable.h"
#include "timeout.h"

#define DEFAULT_BAUDRATE 115200U

#define ENDPOINT_TYPE_UART "UART"
#define ENDPOINT_TYPE_UDP  "UDP"
#define ENDPOINT_TYPE_TCP  "TCP"
#define ENDPOINT_TYPE_LOG  "Log"

struct UartEndpointConfig {
    std::string name;
    std::string device;
    std::vector<uint32_t> baudrates;
    bool flowcontrol{false};
    std::vector<uint32_t> allow_msg_id_out;
    std::vector<uint8_t> allow_src_comp_out;
    std::string group;
};

struct UdpEndpointConfig {
    enum class Mode { Undefined = 0, Server, Client };

    std::string name;
    std::string address;
    unsigned long port;
    Mode mode;
    std::vector<uint32_t> allow_msg_id_out;
    std::vector<uint8_t> allow_src_comp_out;
    std::string group;
};

struct TcpEndpointConfig {
    std::string name;
    std::string address;
    unsigned long port;
    int retry_timeout{5};
    std::vector<uint32_t> allow_msg_id_out;
    std::vector<uint8_t> allow_src_comp_out;
    std::string group;
};

/*
 * mavlink 2.0 packet in its wire format
 *
 * Packet size:
 *      sizeof(mavlink_router_mavlink2_header)
 *      + payload length
 *      + 2 (checksum)
 *      + signature (0 if not signed)
 */
struct _packed_ mavlink_router_mavlink2_header {
    uint8_t magic;
    uint8_t payload_len;
    uint8_t incompat_flags;
    uint8_t compat_flags;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint32_t msgid : 24;
};

/*
 * mavlink 1.0 packet in its wire format
 *
 * Packet size:
 *      sizeof(mavlink_router_mavlink1_header)
 *      + payload length
 *      + 2 (checksum)
 */
struct _packed_ mavlink_router_mavlink1_header {
    uint8_t magic;
    uint8_t payload_len;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint8_t msgid;
};

/// Compare two addresses for equality.
static bool operator==(const struct sockaddr_in& lhs, const struct sockaddr_in& rhs)
{
    return lhs.sin_addr.s_addr == rhs.sin_addr.s_addr && lhs.sin_port == rhs.sin_port;
}

/// Compare two addresses for inequality.
static bool operator!=(const struct sockaddr_in& lhs, const struct sockaddr_in& rhs)
{
    return lhs.sin_addr.s_addr != rhs.sin_addr.s_addr || lhs.sin_port != rhs.sin_port;
}

/// Compare two addreses for ordering.
static bool operator<(const struct sockaddr_in& lhs, const struct sockaddr_in& rhs)
{
    if (lhs.sin_addr.s_addr < rhs.sin_addr.s_addr)
        return true;
    if (lhs.sin_addr.s_addr > rhs.sin_addr.s_addr)
        return false;
    return lhs.sin_port < rhs.sin_port;
}

/// Compare two addresses for equality.
static bool operator==(const struct sockaddr_in6& lhs, const struct sockaddr_in6& rhs)
{
    return IN6_ARE_ADDR_EQUAL(&lhs.sin6_addr, &rhs.sin6_addr) && lhs.sin6_port == rhs.sin6_port && lhs.sin6_scope_id == rhs.sin6_scope_id;
}

/// Compare two addresses for inequality.
static bool operator!=(const struct sockaddr_in6& lhs, const struct sockaddr_in6& rhs)
{
    return !IN6_ARE_ADDR_EQUAL(&lhs.sin6_addr, &rhs.sin6_addr) || lhs.sin6_port != rhs.sin6_port || lhs.sin6_scope_id != rhs.sin6_scope_id;
}

/// Compare two addreses for ordering.
static bool operator<(const struct sockaddr_in6& lhs, const struct sockaddr_in6& rhs)
{
    int result = memcmp(&lhs.sin6_addr, &rhs.sin6_addr, sizeof(struct in6_addr));
    if (result < 0)
        return true;
    if (result > 0)
        return false;
    if (lhs.sin6_scope_id < rhs.sin6_scope_id)
        return true;
    if (lhs.sin6_scope_id > rhs.sin6_scope_id)
        return false;
    return lhs.sin6_port < rhs.sin6_port;
}

/// C++ class for MAVLink system
class MAVLinkSystem {
public:
    /// Default constructor
    MAVLinkSystem()
    {
        system_id_ = 1;
    }

    /// Copy constructor
    MAVLinkSystem(const MAVLinkSystem& other)
        : system_id_(other.system_id_)
        , component_ids_(other.component_ids_)
    {
    }

    /// Move constructor
    MAVLinkSystem(MAVLinkSystem&& other)
        : system_id_(other.system_id_)
        , component_ids_(std::move(other.component_ids_))
    {
    }

    int get_system_id() const
    {
        return static_cast<int>(system_id_);
    }

    void set_system_id(int system_id)
    {
        if (system_id > 0 && system_id != system_id_)
            system_id_ = static_cast<uint8_t>(system_id);
    }

    void add_component(int component_id)
    {
        if (component_id == 0 || component_id == -1)
            return;
        for (auto it = component_ids_.begin(); it != component_ids_.end(); it++) {
            if (*it == static_cast<uint8_t>(component_id))
                return;
        }
        component_ids_.push_back(static_cast<uint8_t>(component_id));
    }

    bool has_system(int system_id) const
    {
        if (system_id == 0 || system_id == -1)
            return true;
        return get_system_id() == system_id;
    }

    bool has_component(int component_id) const
    {
        if (component_id == 0 || component_id == -1)
            return true;
        for (auto it = component_ids_.begin(); it != component_ids_.end(); it++) {
            if (*it == static_cast<uint8_t>(component_id))
                return true;
        }
        return false;
    }

    bool has_autopilot() const
    {
        for (auto it = component_ids_.begin(); it != component_ids_.end(); it++) {
            if (*it == MAV_COMP_ID_AUTOPILOT1)
                return true;
        }
        return false;
    }

    bool has_camera() const
    {
        for (auto it = component_ids_.begin(); it != component_ids_.end(); it++) {
            if (*it >= 	MAV_COMP_ID_CAMERA && *it <= MAV_COMP_ID_CAMERA6)
                return true;
        }
        return false;
    }

    bool has_gimbal() const
    {
        for (auto it = component_ids_.begin(); it != component_ids_.end(); it++) {
            if (*it == MAV_COMP_ID_GIMBAL)
                return true;
            else if (*it >= MAV_COMP_ID_GIMBAL2 && *it <= MAV_COMP_ID_GIMBAL6)
                return true;
        }
        return false;
    }

    bool operator==(const MAVLinkSystem& other)
    {
        return system_id_ == other.system_id_;
    }

    bool operator!=(const MAVLinkSystem& other)
    {
        return system_id_ != other.system_id_;
    }

    bool operator<(const MAVLinkSystem& other)
    {
        return system_id_ < other.system_id_;
    }

private:
    uint8_t system_id_;
    std::vector<uint8_t> component_ids_;
};

/// C++ class for struct sockaddr
class Sockaddress {
public:
    typedef union {
        struct sockaddr         base;
        struct sockaddr_in      v4;
        struct sockaddr_in6     v6;
        struct sockaddr_storage storage;
    } sock_type;

    /// Default constructor.
    Sockaddress() {
        sockaddr_.v4.sin_family = AF_INET;
        sockaddr_.v4.sin_port = 0;
        sockaddr_.v4.sin_addr.s_addr = INADDR_ANY;
    }
    /// Construct from a IPv4 sock address.
    explicit Sockaddress(const sock_type& sockaddr)
    {
        memcpy(&sockaddr_, &sockaddr, sizeof(sockaddr_));
    }
    /// Construct from a IPv4 sock address.
    explicit Sockaddress(const struct sockaddr_in& v4)
    {
        sockaddr_.v4 = v4;
    }
    /// Construct from a IPv6 sock address.
    explicit Sockaddress(const struct sockaddr_in6& v6)
    {
        sockaddr_.v6 = v6;
    }
    /// Copy constructor
    Sockaddress(const Sockaddress& other)
    {
        sockaddr_ = other.sockaddr_;
    }
    /// Assignment
    Sockaddress& operator=(const Sockaddress& other)
    {
        sockaddr_ = other.sockaddr_;
        return *this;
    }

    /// Convert to string in format of ip:port
    std::string to_string()
    {
        char addr_str[256];

        if (sockaddr_.base.sa_family == AF_INET) {
            const char *addr = inet_ntop(AF_INET, &sockaddr_.v4.sin_addr, addr_str, INET_ADDRSTRLEN);
            if (addr == 0)
                return std::string();
            return format("%s:%u", addr, sockaddr_.v4.sin_port);
        } else if (sockaddr_.base.sa_family == AF_INET6) {
            const char *addr = inet_ntop(AF_INET, &sockaddr_.v6.sin6_addr, addr_str, INET6_ADDRSTRLEN);
            if (addr == 0)
                return std::string();
            bool is_local_link = IN6_IS_ADDR_LINKLOCAL(&sockaddr_.v6.sin6_addr);
            if (is_local_link) {
                if (sockaddr_.v6.sin6_scope_id != 0) {
                    char ifname[IF_NAMESIZE + 1] = "%";
                    if (if_indextoname(sockaddr_.v6.sin6_scope_id, ifname + 1)) {
                        strcat(addr_str, ifname);
                    }
                }
            }
            return format("%s:%u", addr, sockaddr_.v6.sin6_port);
        }

        return std::string();
    }

    /// Get native sock address
    const struct sockaddr* addr() const
    {
        return &sockaddr_.base;
    }
    /// Get native size of sock
    ssize_t addrlen() const
    {
        if (sockaddr_.base.sa_family == AF_INET)
            return sizeof(struct sockaddr_in);
        else if (sockaddr_.base.sa_family == AF_INET6)
            return sizeof(struct sockaddr_in6);
        return 0;
    }
    /// Compare for equality
    bool operator==(const Sockaddress& other) const
    {
        if (sockaddr_.base.sa_family != other.sockaddr_.base.sa_family)
            return false;
        if (sockaddr_.base.sa_family == AF_INET)
            return sockaddr_.v4 == other.sockaddr_.v4;
        if (sockaddr_.base.sa_family == AF_INET6)
            return sockaddr_.v6 == other.sockaddr_.v6;
        return false;
    }
    /// Compare for inequality
    bool operator!=(const Sockaddress& other) const
    {
        if (sockaddr_.base.sa_family != other.sockaddr_.base.sa_family)
            return true;
        if (sockaddr_.base.sa_family == AF_INET)
            return sockaddr_.v4 != other.sockaddr_.v4;
        if (sockaddr_.base.sa_family == AF_INET6)
            return sockaddr_.v6 != other.sockaddr_.v6;
        return true;
    }
    /// For ordering
    bool operator<(const Sockaddress& other) const
    {
        if (sockaddr_.base.sa_family < other.sockaddr_.base.sa_family)
            return true;
        if (sockaddr_.base.sa_family > other.sockaddr_.base.sa_family)
            return false;
        if (sockaddr_.base.sa_family == AF_INET)
            return sockaddr_.v4 < other.sockaddr_.v4;
        if (sockaddr_.base.sa_family == AF_INET6)
            return sockaddr_.v6 < other.sockaddr_.v6;
        return true;
    }

private:
    std::string format(const char *format, ...)
    {
        char buffer[1024];
        va_list va;

        va_start(va, format);
        vsnprintf(buffer, sizeof(buffer), format, va);
        va_end(va);

        return std::string(buffer);
    }

private:
    sock_type sockaddr_;
};

class Endpoint : public Pollable {
public:
    using MAVLinkSystemCollection = std::vector<MAVLinkSystem>;
    using MAVLinkSockaddress = std::pair<Sockaddress, MAVLinkSystemCollection>;
    using MAVLinkSockaddressCollection = std::vector<MAVLinkSockaddress>;

    /*
     * Success returns for @read_msg()
     */
    enum read_msg_result {
        ReadOk = 1,
        ReadUnkownMsg,
    };

    /**
     * Return values for @accept_msg()
     */
    enum class AcceptState {
        Accepted = 1,
        Filtered,
        Rejected,
    };

    Endpoint(std::string type, std::string name);
    ~Endpoint() override;

    int handle_read() override;
    virtual int handle_msg(struct buffer* pbuf);
    bool handle_canwrite() override;

    virtual void print_statistics();
    virtual int write_msg(const struct buffer *pbuf) = 0;
    virtual int flush_pending_msgs() = 0;

    void log_aggregate(unsigned int interval_sec);

    static uint8_t get_trimmed_zeros(const mavlink_msg_entry_t *msg_entry,
                                     const struct buffer *buffer);

    bool has_sys_id(unsigned sysid) const;
    bool has_sys_comp_id(unsigned sys_comp_id) const;
    bool has_sys_comp_id(unsigned sysid, unsigned compid) const
    {
        uint16_t sys_comp_id = ((sysid & 0xff) << 8) | (compid & 0xff);
        return has_sys_comp_id(sys_comp_id);
    }

    AcceptState accept_msg(const struct buffer *pbuf) const;

    void filter_add_allowed_msg_id(uint32_t msg_id) { _allowed_msg_ids.push_back(msg_id); }
    void filter_add_allowed_src_comp(uint8_t src_comp) { _allowed_src_comps.push_back(src_comp); }

    bool allowed_by_dedup(const buffer *pbuf) const;

    void link_group_member(std::shared_ptr<Endpoint> other);

    std::string get_type() const { return this->_type; }
    std::string get_group_name() const { return this->_group_name; };

    struct buffer rx_buf;
    struct buffer tx_buf;

    // An endpoint with this system id becomes a "sniffer" and all
    // messages are accepted.
    static uint16_t sniffer_sysid;

protected:
    virtual int read_msg(struct buffer *pbuf);
    virtual ssize_t _read_msg(uint8_t *buf, size_t len) = 0;
    bool _check_crc(const mavlink_msg_entry_t *msg_entry) const;
    void _add_sys_comp_id(uint8_t sysid, uint8_t compid);

    const std::string _type; ///< UART, UDP, TCP, Log
    std::string _name;       ///< Endpoint name from config file
    size_t _last_packet_len = 0;

    std::string _group_name{}; // empty name to disable endpoint groups
    std::vector<std::shared_ptr<Endpoint>> _group_members{};

    // Statistics
    struct {
        struct {
            uint64_t crc_error_bytes = 0;
            uint64_t handled_bytes = 0;
            uint32_t total = 0; // handled + crc error + seq lost
            uint32_t crc_error = 0;
            uint32_t handled = 0;
            uint32_t drop_seq_total = 0;
            uint8_t expected_seq = 0;
        } read;
        struct {
            uint64_t bytes = 0;
            uint32_t total = 0;
        } write;
    } _stat;

    uint32_t _incomplete_msgs = 0;
    std::vector<uint16_t> _sys_comp_ids;

private:
    std::vector<uint32_t> _allowed_msg_ids;
    std::vector<uint8_t> _allowed_src_comps;
};

class UartEndpoint : public Endpoint {
public:
    UartEndpoint(std::string name);
    ~UartEndpoint() override;

    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    bool setup(const UartEndpointConfig &config); ///< open UART device and apply config

    static const ConfFile::OptionsTable option_table[];
    static const char *section_pattern;
    static bool validate_config(const UartEndpointConfig &config);

protected:
    bool open(const char *path);
    int set_speed(speed_t baudrate);
    int set_flow_control(bool enabled);
    int add_speeds(const std::vector<speed_t> &bauds);

    int read_msg(struct buffer *pbuf) override;
    ssize_t _read_msg(uint8_t *buf, size_t len) override;

private:
    size_t _current_baud_idx = 0;
    Timeout *_change_baud_timeout = nullptr;
    std::vector<uint32_t> _baudrates;

    bool _change_baud_cb(void *data);
};

class UdpEndpoint : public Endpoint {
public:
    UdpEndpoint(std::string name);
    ~UdpEndpoint() override;

    int handle_msg(struct buffer* pbuf) override;
    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    bool setup(const UdpEndpointConfig &config); ///< open socket and apply config

    static const ConfFile::OptionsTable option_table[];
    static const char *section_pattern;
    static int parse_udp_mode(const char *val, size_t val_len, void *storage, size_t storage_len);
    static bool validate_config(const UdpEndpointConfig &config);

    static std::shared_ptr<Endpoint> from();
protected:
    bool open(const char *ip, unsigned long port,
              UdpEndpointConfig::Mode mode = UdpEndpointConfig::Mode::Client);
    int open_ipv4(const char *ip, unsigned long port, UdpEndpointConfig::Mode mode);
    int open_ipv6(const char *ip, unsigned long port, UdpEndpointConfig::Mode mode);

    ssize_t _read_msg(uint8_t *buf, size_t len) override;

    Sockaddress::sock_type config_sock;
    Timeout *nomessage_timeout = nullptr;
    bool _nomessage_timeout_cb(void *data);

private:
    bool is_ipv6;
    bool is_server;
    Sockaddress::sock_type sockaddr_;
    Endpoint::MAVLinkSockaddressCollection sockaddr_senders_;
};

class TcpEndpoint : public Endpoint {
public:
    TcpEndpoint(std::string name);
    ~TcpEndpoint() override;

    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }
    bool is_valid() override { return _valid; };
    bool is_critical() override { return false; };

    Endpoint::AcceptState accept_msg(const struct buffer *pbuf) const;

    int accept(int listener_fd);        ///< accept incoming connection
    bool setup(const TcpEndpointConfig &conf); ///< open connection and apply config
    bool reopen();                      ///< re-try connecting to the server
    void close();

    static const ConfFile::OptionsTable option_table[];
    static const char *section_pattern;
    static bool validate_config(const TcpEndpointConfig &config);

protected:
    bool open(const std::string &ip, unsigned long port);
    static int open_ipv4(const char *ip, unsigned long port, sockaddr_in &sockaddr);
    static int open_ipv6(const char *ip, unsigned long port, sockaddr_in6 &sockaddr6);

    ssize_t _read_msg(uint8_t *buf, size_t len) override;

    void _schedule_reconnect();
    bool _retry_timeout_cb(void *data);

private:
    std::string _ip{};
    unsigned long _port = 0;
    bool _valid = true;

    bool is_ipv6;
    int _retry_timeout = 0; // disable retry by default
    struct sockaddr_in sockaddr;
    struct sockaddr_in6 sockaddr6;
};
