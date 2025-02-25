#!/usr/bin/env php
<?php

const MAGIC_COOKIE = 0x2112A442;

final class StunAttr {
    /* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml */
    const MAPPED_ADDRESS                    = 0x0001;
    const USERNAME                          = 0x0006;
    const MESSAGE_INTEGRITY                 = 0x0008;
    const ERROR_CODE                        = 0x0009;
    const UNKNOWN_ATTRIBUTES                = 0x000A;
    const CHANNEL_NUMBER                    = 0x000C;
    const LIFETIME                          = 0x000D;
    const XOR_PEER_ADDRESS                  = 0x0012;
    const DATA                              = 0x0013;
    const REALM                             = 0x0014;
    const NONCE                             = 0x0015;
    const XOR_RELAYED_ADDRESS               = 0x0016;
    const REQUESTED_ADDRESS_FAMILY          = 0x0017;
    const EVEN_PORT                         = 0x0018;
    const REQUESTED_TRANSPORT               = 0x0019;
    const DONT_FRAGMENT                     = 0x001A;
    const ACCESS_TOKEN                      = 0x001B;
    const MESSAGE_INTEGRITY_SHA256          = 0x001C;
    const PASSWORD_ALGORITHM                = 0x001D;
    const USERHASH                          = 0x001E;
    const XOR_MAPPED_ADDRESS                = 0x0020;
    const RESERVATION_TOKEN                 = 0x0022;
    const PRIORITY                          = 0x0024;
    const USE_CANDIDATE                     = 0x0025;
    const PADDING                           = 0x0026;
    const RESPONSE_PORT                     = 0x0027;
    const CONNECTION_ID                     = 0x002A;
    const ADDITIONAL_ADDRESS_FAMILY         = 0x8000;
    const ADDRESS_ERROR_CODE                = 0x8001;
    const PASSWORD_ALGORITHMS               = 0x8002;
    const ALTERNATE_DOMAIN                  = 0x8003;
    const ICMP                              = 0x8004;
    const SOFTWARE                          = 0x8022;
    const ALTERNATE_SERVER                  = 0x8023;
    const TRANSACTION_TRANSMIT_COUNTER      = 0x8025;
    const CACHE_TIMEOUT                     = 0x8027;
    const FINGERPRINT                       = 0x8028;
    const ICE_CONTROLLED                    = 0x8029;
    const ICE_CONTROLLING                   = 0x802A;
    const RESPONSE_ORIGIN                   = 0x802B;
    const OTHER_ADDRESS                     = 0x802C;
    const ECN_CHECK_STUN                    = 0x802D;
    const THIRD_PARTY_AUTHORIZATION         = 0x802E;
    const MOBILITY_TICKET                   = 0x8030;
    const CISCO_STUN_FLOWDATA               = 0xC000;
    const ENF_FLOW_DESCRIPTION              = 0xC001;
    const ENF_NETWORK_STATUS                = 0xC002;
    const CISCO_WEBEX_FLOW_INFO             = 0xC003;
    const CITRIX_TRANSACTION_ID             = 0xC056;
    const GOOG_NETWORK_INFO                 = 0xC057;
    const GOOG_LAST_ICE_CHECK_RECEIVED      = 0xC058;
    const GOOG_MISC_INFO                    = 0xC059;
    const GOOG_OBSOLETE_1                   = 0xC05A;
    const GOOG_CONNECTION_ID                = 0xC05B;
    const GOOG_DELTA                        = 0xC05C;
    const GOOG_DELTA_ACK                    = 0xC05D;
    const GOOG_DELTA_SYNC_REQ               = 0xC05E;
    const GOOG_MESSAGE_INTEGRITY_32         = 0xC060;
    const META_DTLS_IN_STUN                 = 0xC070;
    const META_DTLS_IN_STUN_ACKNOWLEDGEMENT = 0xC071;
}

enum AddressFamily: int {
    case IPV4 = 0x01;
    case IPV6 = 0x02;
}

$s = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

$ok = socket_connect($s, "127.0.0.1", 3478);
//$ok = socket_connect($s, "stun.l.google.com", 19302);

if (! $ok) {
    throw new Exception('error: unable to connect');
}

function make_binding_request(): array
{
    return [
        join([
              pack('n', 0x0001)         // Message Type: Binding Request ; 2 bytes
            , pack('n', 0x0000)         // Message Length: 0             ; 2 bytes
            , pack('N', MAGIC_COOKIE)   //                               ; 4 bytes
            , $tid = random_bytes(12)   // Transaction ID                ; 12 bytes
        ]),
        $tid,
    ];
}

function parse_binding_response(string $response): array
{
    $header = substr($response, 0, 20);
    [$msg_type, $msg_length, $magic_cookie] = array_values(unpack('nt/nl/Nc', $response));

    $tid = substr($header, 8, 12);

    $attrs = [];

    $offset = 20;

    while ($offset < 20 + $msg_length) {
        [$attr_type, $attr_length] = array_values(unpack('nt/nl', $response, $offset));

        $attrs[$attr_type] = substr($response, $offset + 2 * 2, $attr_length);

        $offset += 4 + $attr_length;
    }

    return [
        'message_type' => $msg_type,
        'message_length' => $msg_length,
        'magic_cookie' => $magic_cookie,
        'transaction_id' => $tid,
        'attributes' => $attrs,
    ];
}

function todo(string $msg = '') {
    throw new Exception("todo: $msg");
}

function unpack_xor_mapped_address(string $value, string $tid): array
{
    $xma_header = unpack('N', $value)[1];
    $family_val = ($xma_header >> 16) & 0xFF;
    $xport = ($xma_header >> 0) & 0xFFFF;
    $port = $xport ^ (MAGIC_COOKIE >> 16) & 0xFFFF;

    $family = AddressFamily::from($family_val);

    if ($family === AddressFamily::IPV6) {
        todo("implement ipv6 unpacking");
    }

    $xaddr = unpack('N', substr($value, 4))[1];
    $long_ip = $xaddr ^ MAGIC_COOKIE;

    $ip = sprintf("%d.%d.%d.%d",
        ($long_ip >> 24) & 0xFF,
        ($long_ip >> 16) & 0xFF,
        ($long_ip >> 8) & 0xFF,
        ($long_ip >> 0) & 0xFF,
    );

    return [
        'family' => $family,
        'ip' => $ip,
        'port' => $port,
    ];
}

function unpack_mapped_address(string $value, string $tid): array
{
    $ma_header = unpack('N', substr($value, 0, 4))[1];
    $family_val = ($ma_header >> 16) & 0xFF;
    $port = ($ma_header >> 0) & 0xFFFF;
    $long_ip = unpack('N', substr($value, 4))[1];

    $family = AddressFamily::from($family_val);

    if ($family === AddressFamily::IPV6) {
        todo("implement ipv6 unpacking");
    }

    $ip = sprintf("%d.%d.%d.%d",
        ($long_ip >> 24) & 0xFF,
        ($long_ip >> 16) & 0xFF,
        ($long_ip >> 8) & 0xFF,
        ($long_ip >> 0) & 0xFF,
    );

    return [
        'family' => $family,
        'ip' => $ip,
        'port' => $port,
    ];
}

[$msg, $tid] = make_binding_request();

$ok = socket_write($s, $msg);
if (! $ok) {
    throw new Exception('error: unable to send a message');
}

$response = socket_read($s, 2 << 9);
if ($response === false) {
    throw new Exception('error: unable to read from socket');
}

['message_type' => $message_type, 'transaction_id' => $response_tid, 'attributes' => $attrs] = parse_binding_response($response);

if ($tid !== $response_tid) {
    throw new Exception('error: transaction id mismatch');
}

$unpacked = [];
if (isset($attrs[StunAttr::XOR_MAPPED_ADDRESS])) {
    $unpacked = unpack_xor_mapped_address($attrs[StunAttr::XOR_MAPPED_ADDRESS], $tid);
} else if (isset($attrs[StunAttr::MAPPED_ADDRESS])) {
    $unpacked = unpack_mapped_address($attrs[StunAttr::MAPPED_ADDRESS], $tid);
} else {
    throw new Exception('error: no mapped address attribute received');
}

var_dump($unpacked['ip']);
