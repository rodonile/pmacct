## Test Description (113-IPFIXv10-IPv6-HUAWEI-SRv6-MPLS_in_IP)

IPFIXv10 from a BNG exporting SRv6-encapsulated traffic where the outer IPv6 header carries
MPLS-in-IP (protocol 137) and the inner layer is IPv6.

The template exports two IPv6 layers (outer SRv6 tunnel + inner customer packet), so
`NF_evaluate_flow_type()` must classify the flow as `PM_FTYPE_SRV6_IPV6`: the outer header is
reported via the `tunnel_*` primitives and the inner header via the regular primitives.

`tunnel_flow_label` is intentionally not aggregated: the outer `ipv6FlowLabel` is exported with
a 3-byte reduced-size encoding, which `NF_tunnel_flow_label_handler()` does not decode correctly yet.

All other IEs of template 6042 are covered, either by native primitives or via custom primitives:

| IE (PEN:ID)          | Name                         | Primitive                    |
|----------------------|------------------------------|------------------------------|
| 27/28 (x2)           | IPv6 src/dst addr            | tunnel_src/dst_host, src/dst_host |
| 62                   | ipNextHopIPv6Address         | ipv6_next_hop (custom)       |
| 63                   | bgpNextHopIPv6Address        | peer_dst_ip                  |
| 21/22 + 160          | flowEnd/Start SysUpTime      | timestamp_start/end          |
| 160                  | systemInitTimeMilliseconds   | system_init_time_msec (custom) |
| 10/14                | ingress/egressInterface      | in_iface/out_iface           |
| 16/17                | bgpSource/DestinationAsNumber| src_as/dst_as                |
| 7/11 (x2)            | src/dst port                 | tunnel_src/dst_port, src/dst_port |
| 58/59                | vlanId/postVlanId            | in_vlan/out_vlan             |
| 2011:232             | Huawei private               | huawei_232 (custom)          |
| 6/4/5 (x2)           | tcp flags/protocol/tos       | tunnel_tcpflags/proto/tos, tcpflags/proto/tos |
| 29/30                | src/dst IPv6 mask            | src_mask/dst_mask            |
| 61                   | flowDirection                | direction (custom)           |
| 89                   | forwardingStatus             | fwd_status                   |
| 31 (x2)              | flowLabelIPv6                | flow_label (inner only)      |
| 136                  | flowEndReason                | flow_end_reason (custom)     |
| 243                  | dot1qVlanId                  | dot1q_vlan_id (custom)       |
| 245                  | dot1qCustomerVlanId          | in_cvlan                     |
| 244                  | dot1qPriority                | cos                          |
| 246                  | dot1qCustomerPriority        | dot1q_customer_priority (custom) |
| 234/235              | ingress/egressVRFID          | vrf_id_ingress/egress (custom) |
| 302                  | selectorId                   | selector_id (custom)         |
| 515                  | unknown                      | ie_515 (custom)              |
| 80/56                | dst/src MAC                  | dst_mac/src_mac              |
| 492                  | srhFlagsIPv6                 | srhFlagsIPv6 (custom)        |
| 493                  | srhTagIPv6                   | srhTagIPv6 (custom)          |
| 495                  | srhActiveSegmentIPv6         | srhActiveSegmentIPv6 (custom)|
| 497                  | srhSegmentIPv6ListSection    | srv6_seg_ipv6_list           |
| 498                  | srhSegmentsIPv6Left          | srhSegmentsIPv6Left (custom) |
| 500                  | srhIPv6ActiveSegmentType     | srhIPv6ActiveSegmentType (custom) |

### Provided files:
```
- 113_test.py                    pytest file defining test execution

- traffic-00.pcap                pcap file (for traffic generator)
- traffic-reproducer-00.yml      traffic replay function config file

- nfacctd-00.conf                nfacctd daemon configuration file

- pmacct_mount/pretag-00.map     pretag mapping file for nfacctd           HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map  custom primitives for IEs without a native pmacct primitive

- output-flow-00.json            desired nfacctd kafka output [daisy.flow topic] containing json messages
```

### Scenario

| Layer | Src                     | Dst                     | Protocol        | Flow Label |
|-------|-------------------------|-------------------------|-----------------|------------|
| Outer | fd7c:3f00:a12:e000::1   | fd7c:3f00:a13::         | 137 (MPLS-in-IP)| 877822     |
| Inner | 2001:918:ffff::504:2    | 2a02:1211:e000:600::1   | 59 (No Next Hdr)| 7          |

### Test timeline:

t=0s → traffic-reproducer startup

- t=0s:   IPFIX Template (ID 6042) sent
- t=2s:   IPFIX Data Record (1 flow) sent
