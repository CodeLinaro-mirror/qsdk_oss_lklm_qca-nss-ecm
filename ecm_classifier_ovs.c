/*
 **************************************************************************
 * Copyright (c) 2019-2020, The Linux Foundation.  All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * OVS Classifier.
 * This classifier is called for the connections which are created
 * on OVS interfaces. The connections can be routed or bridged connections.
 * The classifier processes these connection flows and decides if the connection
 * is ready to be accelerated. Moreover, it has an interface to an external classifier
 * to make smart decisions on the flows, such as extracting the VLAN information from the
 * OVS flow tables and gives it to the ECM front end to be passed to the acceleration engine.
 */
#include <linux/version.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/etherdevice.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CLASSIFIER_OVS_DEBUG_LEVEL

#include <ovsmgr.h>
#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_state.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_datagram.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_classifier_ovs.h"
#include "ecm_classifier_ovs_public.h"
#include "ecm_front_end_common.h"
#include "ecm_front_end_ipv4.h"
#ifdef ECM_IPV6_ENABLE
#include "ecm_front_end_ipv6.h"
#endif
#include "ecm_interface.h"

/*
 * Magic numbers
 */
#define ECM_CLASSIFIER_OVS_INSTANCE_MAGIC 0x2568

/*
 * struct ecm_classifier_ovs_instance
 * 	State per connection for OVS classifier
 */
struct ecm_classifier_ovs_instance {
	struct ecm_classifier_instance base;			/* Base type */

	uint32_t ci_serial;					/* RO: Serial of the connection */

	struct ecm_classifier_ovs_instance *next;		/* Next classifier state instance (for accouting and reporting purposes) */
	struct ecm_classifier_ovs_instance *prev;		/* Next classifier state instance (for accouting and reporting purposes) */

	struct ecm_classifier_process_response process_response;
								/* Last process response computed */
	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Operational control.
 */
static int ecm_classifier_ovs_enabled = 1;			/* Operational behaviour */

/*
 * Management thread control
 */
static bool ecm_classifier_ovs_terminate_pending;	/* True when the user wants us to terminate */

/*
 * Debugfs dentry object.
 */
static struct dentry *ecm_classifier_ovs_dentry;

/*
 * Locking of the classifier structures
 */
static DEFINE_SPINLOCK(ecm_classifier_ovs_lock);			/* Protect SMP access. */

/*
 * List of our classifier instances
 */
static struct ecm_classifier_ovs_instance *ecm_classifier_ovs_instances = NULL;
								/* list of all active instances */
static int ecm_classifier_ovs_count = 0;			/* Tracks number of instances allocated */

/*
 * Callback object.
 */
static struct ecm_classifier_ovs_callbacks ovs;

/*
 * ecm_classifier_ovs_ref()
 *	Ref
 */
static void ecm_classifier_ovs_ref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)ci;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->refs++;
	DEBUG_ASSERT(ecvi->refs > 0, "%p: ref wrap\n", ecvi);
	DEBUG_TRACE("%p: ecvi ref %d\n", ecvi, ecvi->refs);
	spin_unlock_bh(&ecm_classifier_ovs_lock);
}

/*
 * ecm_classifier_ovs_deref()
 *	Deref
 */
static int ecm_classifier_ovs_deref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)ci;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->refs--;
	DEBUG_ASSERT(ecvi->refs >= 0, "%p: refs wrapped\n", ecvi);
	DEBUG_TRACE("%p: ecvi deref %d\n", ecvi, ecvi->refs);
	if (ecvi->refs) {
		int refs = ecvi->refs;
		spin_unlock_bh(&ecm_classifier_ovs_lock);
		return refs;
	}

	/*
	 * Object to be destroyed
	 */
	ecm_classifier_ovs_count--;
	DEBUG_ASSERT(ecm_classifier_ovs_count >= 0, "%p: ecm_classifier_ovs_count wrap\n", ecvi);

	/*
	 * UnLink the instance from our list
	 */
	if (ecvi->next) {
		ecvi->next->prev = ecvi->prev;
	}
	if (ecvi->prev) {
		ecvi->prev->next = ecvi->next;
	} else {
		DEBUG_ASSERT(ecm_classifier_ovs_instances == ecvi, "%p: list bad %p\n", ecvi, ecm_classifier_ovs_instances);
		ecm_classifier_ovs_instances = ecvi->next;
	}
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	/*
	 * Final
	 */
	DEBUG_INFO("%p: Final ovs classifier instance\n", ecvi);
	kfree(ecvi);

	return 0;
}

/*
 * ecm_classifier_ovs_interface_get_and_ref()
 *	Gets the OVS bridge port in the specified direction hierarchy.
 */
static inline struct net_device *ecm_classifier_ovs_interface_get_and_ref(struct ecm_db_connection_instance *ci,
									   ecm_db_obj_dir_t dir, bool ovs_port)
{
	int32_t if_first;
	struct ecm_db_iface_instance *interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t i;

	/*
	 * Get the interface hierarchy.
	 */
	if_first = ecm_db_connection_interfaces_get_and_ref(ci, interfaces, dir);
	if (if_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Failed to get %s interfaces list\n", ci, ecm_db_obj_dir_strings[dir]);
		return NULL;
	}

	/*
	 * Go through the hierarchy and get the OVS port.
	 */
	for (i = ECM_DB_IFACE_HEIRARCHY_MAX - 1; i >= if_first; i--) {
		struct net_device *dev = dev_get_by_index(&init_net,
							  ecm_db_iface_interface_identifier_get(interfaces[i]));
		if (!dev) {
			DEBUG_WARN("%p: Failed to get net device with %d index\n", ci, i);
			continue;
		}

		if (ovs_port) {
			if (ecm_interface_is_ovs_bridge_port(dev)) {
				ecm_db_connection_interfaces_deref(interfaces, if_first);
				DEBUG_TRACE("%p: %s_dev: %s at %d index is an OVS bridge port\n", ci, ecm_db_obj_dir_strings[dir], dev->name, i);
				return dev;
			}

		} else {
			if (ovsmgr_is_ovs_master(dev)) {
				ecm_db_connection_interfaces_deref(interfaces, if_first);
				DEBUG_TRACE("%p: %s_dev: %s at %d index is an OVS bridge dev\n", ci, ecm_db_obj_dir_strings[dir], dev->name, i);
				return dev;
			}
		}

		DEBUG_TRACE("%p: dev: %s index: %d\n", ci, dev->name, i);
		dev_put(dev);
	}

	DEBUG_TRACE("%p: No OVS bridge port on the %s direction\n", ci, ecm_db_obj_dir_strings[dir]);
	ecm_db_connection_interfaces_deref(interfaces, if_first);
	return NULL;
}

/*
 * ecm_classifier_ovs_process_route_flow()
 *	Process routed flows.
 */
static void ecm_classifier_ovs_process_route_flow(struct ecm_classifier_ovs_instance *ecvi, struct ecm_db_connection_instance *ci,
							struct sk_buff *skb, struct net_device *from_dev, struct net_device *to_dev,
							struct ecm_classifier_process_response *process_response,
							ecm_classifier_ovs_process_callback_t cb)
{
	ecm_classifier_ovs_result_t result;
	struct ecm_classifier_ovs_process_response resp;
	struct ovsmgr_dp_flow flow;
	struct net_device *br_dev;
	ip_addr_t src_ip, dst_ip;

	memset(&flow, 0, sizeof(flow));

	flow.is_routed = true;
	flow.tuple.ip_version = ecm_db_connection_ip_version_get(ci);
	flow.tuple.protocol = ecm_db_connection_protocol_get(ci);

	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.ingress_vlan_tag[0] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
	ecvi->process_response.egress_vlan_tag[0] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
	ecvi->process_response.ingress_vlan_tag[1] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
	ecvi->process_response.egress_vlan_tag[1] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	/*
	 * For routed flows both from and to side can be OVS bridge port, if there
	 * is a routed flow between two OVS bridges. (e.g: ovs-br1 and ovs-br2)
	 *
	 * Connection Direction:
	 * 				PC1 -----> eth1-ovs-br1 (DUT) ovs-br2-eth2 -----> PC2
							from_dev	to_dev
	 *
	 * 1. SNAT/DNAT Enabled:	FROM				FROM_NAT	TO/TO_NAT
	 * 2. SNAT/DNAT Disabled:	FROM/FROM_NAT					TO/TO_NAT
	 *
	 * Connection Direction:
	 * 				PC1 <----- eth1-ovs-br1 (DUT) ovs-br2-eth2 <----- PC2
	 *						to_dev		from_dev
	 *
	 * 3. SNAT/DNAT Enabled:	TO				TO_NAT		FROM/FROM_NAT
	 * 4. SNAT/DNAT Disabled:	TO/TO_NAT					FROM/FROM_NAT
	 */
	if (from_dev) {
		/*
		 * Case 1/2
		 * from_dev = eth1
		 * br_dev = ovs-br1
		 *
		 * Case 3/4
		 * from_dev = eth2
		 * br_dev = ovs-br2
		 */
		br_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_FROM, false);
		if (!br_dev) {
			DEBUG_WARN("%p: from_dev = %s is a OVS bridge port, bridge interface is not found\n",
					ecvi, from_dev->name);
			goto route_deny_accel;
		}

		DEBUG_TRACE("%p: processing route flow from_dev = %s, br_dev = %s", ecvi, from_dev->name, br_dev->name);

		/*
		 * We always take the flow from bridge to port, so indev is brdige and outdev is port device.
		 */
		flow.indev = br_dev;
		flow.outdev = from_dev;

		flow.tuple.src_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO_NAT));
		flow.tuple.dst_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM));

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO_NAT, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, dst_ip);

		if (flow.tuple.ip_version == 4) {
			ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.src, src_ip);
			ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.dst, dst_ip);
		} else if (flow.tuple.ip_version == 6) {
			ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.src, src_ip);
			ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.dst, dst_ip);
		} else {
			DEBUG_ASSERT(NULL, "%p: unexpected ip_version: %d", ecvi, flow.tuple.ip_version );
		}

		ether_addr_copy(flow.smac, br_dev->dev_addr);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, flow.dmac);

		memset(&resp, 0, sizeof(struct ecm_classifier_ovs_process_response));

		/*
		 * Call the external callback and get the result.
		 */
		result = cb(&flow, skb, &resp);

		dev_put(br_dev);

		/*
		 * Handle the result
		 */
		switch (result) {
		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_ACCEL:
		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL:
			/*
			 * Allow accel after setting the external module response.
			 */
			DEBUG_WARN("%p: External callback process succeeded\n", ecvi);

			spin_lock_bh(&ecm_classifier_ovs_lock);
			if (resp.egress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.ingress_vlan_tag[0] = resp.egress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Ingress vlan tag[0] set : %x\n", ecvi->process_response.ingress_vlan_tag[0]);
			}

			ecvi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_TAG;

			if (result == ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL) {
				if (resp.egress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.ingress_vlan_tag[1] = resp.egress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Ingress vlan tag[0] set : %x\n", ecvi->process_response.ingress_vlan_tag[1]);
				}

				ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_QINQ_TAG;
			}
			spin_unlock_bh(&ecm_classifier_ovs_lock);
			break;

		case ECM_CLASSIFIER_OVS_RESULT_DENY_ACCEL:
			/*
			 * External callback failed to process VLAN process. So, let's deny the acceleration
			 * and try more with the subsequent packets.
			 */
			DEBUG_WARN("%p: External callback failed to process VLAN tags\n", ecvi);
			goto route_deny_accel;

		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_ACCEL:

			/*
			 * There is no VLAN tag in the flow. Just allow the acceleration.
			 */
			DEBUG_WARN("%p: External callback didn't find any VLAN relation\n", ecvi);
			break;

		default:
			DEBUG_ASSERT(false, "Unhandled result: %d\n", result);
		}
	}

	if (to_dev) {
		/*
		 * Case 1/2
		 * from_dev = eth2
		 * br_dev = ovs-br2
		 *
		 * Case 3/4
		 * from_dev = eth1
		 * br_dev = ovs-br1
		 */
		br_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_TO, false);
		if (!br_dev) {
			DEBUG_WARN("%p: to_dev = %s is a OVS bridge port, bridge interface is not found\n",
					ecvi, to_dev->name);
			goto route_deny_accel;
		}

		DEBUG_TRACE("%p: processing route flow to_dev = %s, br_dev = %s", ecvi, to_dev->name, br_dev->name);

		flow.indev = br_dev;
		flow.outdev = to_dev;

		flow.tuple.src_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM_NAT));
		flow.tuple.dst_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO));

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM_NAT, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, dst_ip);

		if (flow.tuple.ip_version == 4) {
			ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.src, src_ip);
			ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.dst, dst_ip);
		} else if (flow.tuple.ip_version == 6) {
			ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.src, src_ip);
			ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.dst, dst_ip);
		} else {
			DEBUG_ASSERT(NULL, "%p: unexpected ip_version: %d", ecvi, flow.tuple.ip_version );
		}

		ether_addr_copy(flow.smac, br_dev->dev_addr);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, flow.dmac);

		memset(&resp, 0, sizeof(struct ecm_classifier_ovs_process_response));

		/*
		 * Call the external callback and get the result.
		 */
		result = cb(&flow, skb, &resp);

		dev_put(br_dev);

		/*
		 * Handle the result
		 */
		switch (result) {
		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_ACCEL:
		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL:
			/*
			 * Allow accel after setting the external module response.
			 */
			DEBUG_WARN("%p: External callback process succeeded\n", ecvi);

			spin_lock_bh(&ecm_classifier_ovs_lock);
			if (resp.egress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.egress_vlan_tag[0] = resp.egress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Egress vlan tag[0] set : %x\n", ecvi->process_response.egress_vlan_tag[0]);
			}

			ecvi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_TAG;

			if (result == ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL) {
				if (resp.egress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.egress_vlan_tag[1] = resp.egress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Ingress vlan tag[0] set : %x\n", ecvi->process_response.ingress_vlan_tag[1]);
				}

				ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_QINQ_TAG;
			}
			spin_unlock_bh(&ecm_classifier_ovs_lock);
			break;

		case ECM_CLASSIFIER_OVS_RESULT_DENY_ACCEL:
			/*
			 * External callback failed to process VLAN process. So, let's deny the acceleration
			 * and try more with the subsequent packets.
			 */
			DEBUG_WARN("%p: External callback failed to process VLAN tags\n", ecvi);
			goto route_deny_accel;

		case ECM_CLASSIFIER_OVS_RESULT_ALLOW_ACCEL:

			/*
			 * There is no VLAN tag in the flow. Just allow the acceleration.
			 */
			DEBUG_WARN("%p: External callback didn't find any VLAN relation\n", ecvi);
			break;

		default:
			DEBUG_ASSERT(false, "Unhandled result: %d\n", result);
		}
	}

	/*
	 * Acceleration is permitted
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;
	ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	ecvi->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	return;

route_deny_accel:
	/*
	 * ecm_classifier_ovs_lock MUST be held
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;
	ecvi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	ecvi->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
}

/*
 * ecm_classifier_ovs_process()
 *	Process new packet
 *
 * NOTE: This function would only ever be called if all other classifiers have failed.
 */
static void ecm_classifier_ovs_process(struct ecm_classifier_instance *aci, ecm_tracker_sender_type_t sender,
									struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb,
									struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_ovs_instance *ecvi = (struct ecm_classifier_ovs_instance *)aci;
	ecm_classifier_ovs_result_t result = 0;
	struct ecm_db_connection_instance *ci;
	ecm_classifier_ovs_process_callback_t cb = NULL;
	ip_addr_t src_ip;
	ip_addr_t dst_ip;
	struct ecm_classifier_ovs_process_response resp;
	struct ovsmgr_dp_flow flow;
	struct net_device *from_dev = NULL;
	struct net_device *to_dev = NULL;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: invalid state magic\n", ecvi);

	/*
	 * Not relevant to the connection if not enabled.
	 */
	if (unlikely(!ecm_classifier_ovs_enabled)) {
		/*
		 * Not relevant.
		 */
		DEBUG_WARN("%p: ovs classifier is not enabled\n", aci);
		goto not_relevant;
	}

	/*
	 * Get connection
	 */
	ci = ecm_db_connection_serial_find_and_ref(ecvi->ci_serial);
	if (!ci) {
		/*
		 * Connection has gone from under us
		 */
		DEBUG_WARN("%p: connection instance gone while processing classifier\n", aci);
		goto not_relevant;
	}

	/*
	 * Get the possible OVS bridge ports. If both are NULL, the classifier is not
	 * relevant to this connection.
	 */
	from_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_FROM, true);
	to_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_TO, true);
	if (!from_dev && !to_dev) {
		/*
		 * So, the classifier is not relevant to this connection.
		 */
		DEBUG_WARN("%p: None of the from/to interfaces are OVS bridge port\n", aci);
		ecm_db_connection_deref(ci);
		goto not_relevant;
	}

	/*
	 * Is there an external callback to get the ovs value from the packet?
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	cb = ovs.ovs_process;
	if (!cb) {
		/*
		 * Allow acceleration.
		 * Keep the classifier relevant to connection for stats update..
		 */
		spin_unlock_bh(&ecm_classifier_ovs_lock);
		DEBUG_WARN("%p: No external process callback set\n", aci);
		if (from_dev)
			dev_put(from_dev);

		if (to_dev)
			dev_put(to_dev);

		spin_lock_bh(&ecm_classifier_ovs_lock);
		goto allow_accel;
	}
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	/*
	 * If the flow is a routed flow, set the is_routed flag of the flow.
	 */
	if (ecm_db_connection_is_routed_get(ci)) {
		ecm_classifier_ovs_process_route_flow(ecvi, ci, skb, from_dev, to_dev, process_response, cb);

		if (from_dev)
			dev_put(from_dev);

		if (to_dev)
			dev_put(to_dev);

		ecm_db_connection_deref(ci);
		return;
	}

	memset(&flow, 0, sizeof(struct ovsmgr_dp_flow));

	/*
	 * If the connection is a bridge flow, both devices should be present.
	 * TODO: This is an unexpected situation and should be assertion.
	 * We should also make sure that both devices are on the same OVS bridge.
	 */
	if (!from_dev || !to_dev) {
		DEBUG_ERROR("%p: One of the ports is NULL from_dev: %p to_dev: %p\n", aci, from_dev, to_dev);

		if (from_dev)
			dev_put(from_dev);

		if (to_dev)
			dev_put(to_dev);

		ecm_db_connection_deref(ci);
		goto not_relevant;
	}

	/*
	 * Flow is an OVS bridge flow.
	 */
	flow.tuple.ip_version = ecm_db_connection_ip_version_get(ci);
	flow.tuple.protocol = ecm_db_connection_protocol_get(ci);

	/*
	 * For the flow lookup, we need to use the  proper 5-tuple, in/out dev and
	 * src/dest MAC address. If the packet is coming from the destination side of the connection
	 * (e.g: ACK packets of the TCP connection) these values should be reversed.
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		DEBUG_TRACE("%p: sender is SRC\n", aci);
		flow.indev = from_dev;
		flow.outdev = to_dev;

		flow.tuple.src_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM));
		flow.tuple.dst_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO));

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, dst_ip);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, flow.smac);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, flow.dmac);
	} else {
		DEBUG_TRACE("%p: sender is DEST\n", aci);
		flow.indev = to_dev;
		flow.outdev = from_dev;

		flow.tuple.src_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO));
		flow.tuple.dst_port = htons(ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM));

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, dst_ip);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, flow.smac);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, flow.dmac);

	}

	if (flow.tuple.ip_version == 4) {
		ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.src, src_ip);
		ECM_IP_ADDR_TO_NIN4_ADDR(flow.tuple.ipv4.dst, dst_ip);
	} else if (flow.tuple.ip_version == 6) {
		ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.src, src_ip);
		ECM_IP_ADDR_TO_NIN6_ADDR(flow.tuple.ipv6.dst, dst_ip);
	} else {
		DEBUG_ASSERT(NULL, "%p: unexpected ip_version: %d", aci, flow.tuple.ip_version );
	}

	memset(&resp, 0, sizeof(struct ecm_classifier_ovs_process_response));

	/*
	 * Call the external callback and get the result.
	 */
	result = cb(&flow, skb, &resp);

	if (from_dev)
		dev_put(from_dev);

	if (to_dev)
		dev_put(to_dev);

	/*
	 * Handle the result
	 */
	switch (result) {
	case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_ACCEL:
	case ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL:
		/*
		 * Allow accel after setting the external module response.
		 */
		DEBUG_WARN("%p: External callback process succeeded\n", aci);

		spin_lock_bh(&ecm_classifier_ovs_lock);
		ecvi->process_response.ingress_vlan_tag[0] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
		ecvi->process_response.egress_vlan_tag[0] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
		ecvi->process_response.ingress_vlan_tag[1] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;
		ecvi->process_response.egress_vlan_tag[1] = ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED;

		/*
		 * Primary VLAN tag is always present even it is QinQ.
		 */
		ecvi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_TAG;

		/*
		 * If the sender type is source, which means the packet is coming from the originator,
		 * we assign the ECM-ingress<>OVS-ingress, ECM-egress<>OVS-egress values.
		 */
		if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
			if (resp.ingress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.ingress_vlan_tag[0] = resp.ingress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.ingress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Ingress vlan tag[0] set : 0x%x\n", ecvi->process_response.ingress_vlan_tag[0]);
			}

			if (resp.egress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.egress_vlan_tag[0] = resp.egress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Egress vlan tag[0] set : 0x%x\n", ecvi->process_response.egress_vlan_tag[0]);
			}

			if (result == ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL) {
				if (resp.ingress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.ingress_vlan_tag[1] = resp.ingress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.ingress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Ingress vlan tag[0] set : 0x%x\n", ecvi->process_response.ingress_vlan_tag[1]);
				}

				if (resp.egress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.egress_vlan_tag[1] = resp.egress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Egress vlan tag[1] set : 0x%x\n", ecvi->process_response.egress_vlan_tag[1]);
				}

				/*
				 * QinQ tag is present. Let's pass this information to the frontend through the process action flag.
				 */
				ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_QINQ_TAG;
			}
		} else {
			/*
			 * Sender type is destination, which means packet si coming from the counter originator side,
			 * we assign the ECM-ingress<>OVS-egress and ECM-egress<>OVS-ingress values.
			 */
			if (resp.ingress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.egress_vlan_tag[0] = resp.ingress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.ingress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Egress vlan tag[0] set : 0x%x\n", ecvi->process_response.egress_vlan_tag[0]);
			}

			if (resp.egress_vlan[0].h_vlan_TCI) {
				ecvi->process_response.ingress_vlan_tag[0] = resp.egress_vlan[0].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[0].h_vlan_TCI;
				DEBUG_TRACE("Ingress vlan tag[0] set : 0x%x\n", ecvi->process_response.ingress_vlan_tag[0]);
			}

			if (result == ECM_CLASSIFIER_OVS_RESULT_ALLOW_VLAN_QINQ_ACCEL) {
				if (resp.ingress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.egress_vlan_tag[1] = resp.ingress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.ingress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Egress vlan tag[0] set : 0x%x\n", ecvi->process_response.egress_vlan_tag[1]);
				}

				if (resp.egress_vlan[1].h_vlan_TCI) {
					ecvi->process_response.ingress_vlan_tag[1] = resp.egress_vlan[1].h_vlan_encapsulated_proto << 16 | resp.egress_vlan[1].h_vlan_TCI;
					DEBUG_TRACE("Ingress vlan tag[1] set : 0x%x\n", ecvi->process_response.ingress_vlan_tag[1]);
				}

				/*
				 * QinQ tag is present. Let's pass this information to the frontend through the process action flag.
				 */
				ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_OVS_VLAN_QINQ_TAG;
			}
		}
		goto allow_accel;

	case ECM_CLASSIFIER_OVS_RESULT_DENY_ACCEL:
		/*
		 * External callback failed to process VLAN process. So, let's deny the acceleration
		 * and try more with the subsequent packets.
		 */
		DEBUG_WARN("%p: External callback failed to process VLAN tags\n", aci);
		goto deny_accel;

	case ECM_CLASSIFIER_OVS_RESULT_ALLOW_ACCEL:

		/*
		 * There is no VLAN tag in the flow. Just allow the acceleration.
		 */
		DEBUG_WARN("%p: External callback didn't find any VLAN relation\n", aci);
		spin_lock_bh(&ecm_classifier_ovs_lock);
		goto allow_accel;

	default:
		DEBUG_ASSERT(false, "Unhandled result: %d\n", result);
	}

allow_accel:
	/*
	 * Acceleration is permitted
	 */
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;
	ecvi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	ecvi->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
	ecm_db_connection_deref(ci);
	return;

not_relevant:
	/*
	 * ecm_classifier_ovs_lock MUST be held
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
	return;

deny_accel:
	/*
	 * ecm_classifier_ovs_lock MUST be held
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;
	ecvi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	ecvi->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_classifier_ovs_type_get()
 *	Get type of classifier this is
 */
static ecm_classifier_type_t ecm_classifier_ovs_type_get(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)aci;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
	return ECM_CLASSIFIER_TYPE_OVS;
}

/*
 * ecm_classifier_ovs_reclassify_allowed()
 *	Get whether reclassification is allowed
 */
static bool ecm_classifier_ovs_reclassify_allowed(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)aci;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
	return true;
}

/*
 * ecm_classifier_ovs_reclassify()
 *	Reclassify
 */
static void ecm_classifier_ovs_reclassify(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)aci;
	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);

	/*
	 * Revert back to MAYBE relevant - we will evaluate when we get the next process() call.
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_MAYBE;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
}

/*
 * ecm_classifier_ovs_last_process_response_get()
 *	Get result code returned by the last process call
 */
static void ecm_classifier_ovs_last_process_response_get(struct ecm_classifier_instance *aci,
	struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_ovs_instance *ecvi;
	ecvi = (struct ecm_classifier_ovs_instance *)aci;
	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);

	spin_lock_bh(&ecm_classifier_ovs_lock);
	*process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
}

/*
 * ecm_classifier_ovs_stats_sync()
 *	Sync the stats of the OVS flow.
 */
static inline void ecm_classifier_ovs_stats_sync(struct ovsmgr_dp_flow *flow,
					  uint32_t tx_pkts, uint32_t tx_bytes,uint32_t rx_pkts,uint32_t rx_bytes,
					  struct net_device *indev, struct net_device *outdev,
					  uint8_t *smac, uint8_t *dmac,
					  ip_addr_t sip, ip_addr_t dip,
					  uint16_t sport, uint16_t dport, uint16_t tci, uint16_t tpid)
{
	struct ovsmgr_dp_flow_stats stats;

	flow->indev = indev;
	flow->outdev = outdev;

	ether_addr_copy(flow->smac, smac);
	ether_addr_copy(flow->dmac, dmac);

	/*
	 * Set default VLAN tci and vlan encapsulated proto.
	 */
	flow->ingress_vlan.h_vlan_TCI = 0;
	flow->ingress_vlan.h_vlan_encapsulated_proto = 0;

	if (tci) {
		flow->ingress_vlan.h_vlan_TCI = tci;
		flow->ingress_vlan.h_vlan_encapsulated_proto = tpid;
	}

	flow->tuple.src_port = sport;
	flow->tuple.dst_port = dport;

	if (flow->tuple.ip_version == 4) {
		ECM_IP_ADDR_TO_NIN4_ADDR(flow->tuple.ipv4.src, sip);
		ECM_IP_ADDR_TO_NIN4_ADDR(flow->tuple.ipv4.dst, dip);
		DEBUG_TRACE("%p: STATS: src MAC: %pM src_dev: %s src: %pI4:%d proto: %d dest: %pI4:%d dest_dev: %s dest MAC: %pM\n",
				flow, flow->smac, flow->indev->name, &flow->tuple.ipv4.src, flow->tuple.src_port, flow->tuple.protocol,
				&flow->tuple.ipv4.dst, flow->tuple.dst_port, flow->outdev->name, flow->dmac);
	} else {
		ECM_IP_ADDR_TO_NIN6_ADDR(flow->tuple.ipv6.src, sip);
		ECM_IP_ADDR_TO_NIN6_ADDR(flow->tuple.ipv6.dst, dip);
		DEBUG_TRACE("%p: STATS: src MAC: %pM src_dev: %s src: %pI6:%d proto: %d dest: %pI6:%d dest_dev: %s dest MAC: %pM\n",
				flow, flow->smac, flow->indev->name, &flow->tuple.ipv6.src, flow->tuple.src_port, flow->tuple.protocol,
				&flow->tuple.ipv6.dst, flow->tuple.dst_port, flow->outdev->name, flow->dmac);
	}

	/*
	 * Set the flow stats and update the flow database.
	 */
	stats.tx_pkts = tx_pkts;
	stats.tx_bytes = tx_bytes;
	stats.rx_pkts = rx_pkts;
	stats.rx_bytes = rx_bytes;

	ovsmgr_flow_stats_update(flow, &stats);
}

/*
 * ecm_classifier_ovs_sync_to_stats()
 *	Common sync_to function for IPv4 and IPv6.
 */
static void ecm_classifier_ovs_sync_to_stats(struct ecm_classifier_instance *aci, struct ecm_classifier_rule_sync *sync)
{
	ip_addr_t src_ip;
	ip_addr_t dst_ip;
	struct ecm_db_connection_instance *ci;
	struct ovsmgr_dp_flow flow;
	struct net_device *from_dev;
	struct net_device *to_dev;
	struct net_device *br_dev;
	uint8_t smac[ETH_ALEN];
	uint8_t dmac[ETH_ALEN];
	uint16_t sport;
	uint16_t dport;
	uint16_t tpid = 0, tci = 0;

	struct ecm_classifier_ovs_instance *ecvi = (struct ecm_classifier_ovs_instance *)aci;

	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);

	ci = ecm_db_connection_serial_find_and_ref(ecvi->ci_serial);
	if (!ci) {
		DEBUG_TRACE("%p: No ci found for %u\n", ecvi, ecvi->ci_serial);
		return;
	}

	memset(&flow, 0, sizeof(flow));
	/*
	 * Get the possible OVS bridge ports.
	 */
	from_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_FROM, true);
	to_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_TO, true);
	DEBUG_ASSERT(from_dev || to_dev, "%p: None of the from/to interfaces is OVS bridge port\n", aci);

	/*
	 * IP version and protocol are common for routed and bridge flows.
	 */
	flow.tuple.ip_version = ecm_db_connection_ip_version_get(ci);
	flow.tuple.protocol = ecm_db_connection_protocol_get(ci);
	flow.is_routed = ecm_db_connection_is_routed_get(ci);

	/*
	 * Get the tci and tpid values of the ingress side of the flow.
	 */
	if (ecvi->process_response.ingress_vlan_tag[0] != ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED) {
		tci = ecvi->process_response.ingress_vlan_tag[0] & 0xffff;
		tpid = (ecvi->process_response.ingress_vlan_tag[0] >> 16) & 0xffff;
		DEBUG_TRACE("%p: Ingress VLAN : %x:%x\n", aci, tci, tpid);
	}

	/*
	 * Bridge flow
	 */
	if (!flow.is_routed) {
		/*
		 * Sync the flow direction (eth1 to eth2)
		 */
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, smac);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, dmac);

		sport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM);
		dport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO);

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, dst_ip);

		DEBUG_TRACE("%p: Flow direction stats update\n", aci);
		ecm_classifier_ovs_stats_sync(&flow,
				  sync->flow_rx_packet_count, sync->flow_rx_byte_count,
				  sync->return_tx_packet_count, sync->return_tx_byte_count,
				  from_dev, to_dev,
				  smac, dmac,
				  src_ip, dst_ip,
				  sport, dport, tci, tpid);

		/*
		 * Sync the return direction (eth2 to eth1)
		 * All the flow parameters are reversed.
		 */
		DEBUG_TRACE("%p: Return direction stats update\n", aci);

		/*
		 * Reset the tci and tpid values and get the egress side of the flow.
		 */
		tci = tpid = 0;
		if (ecvi->process_response.egress_vlan_tag[0] != ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED) {
			tci = ecvi->process_response.egress_vlan_tag[0] & 0xffff;
			tpid = (ecvi->process_response.egress_vlan_tag[0] >> 16) & 0xffff;
			DEBUG_TRACE("%p: Egress VLAN : %x:%x\n", aci, tci, tpid);
		}

		ecm_classifier_ovs_stats_sync(&flow,
				  sync->flow_tx_packet_count, sync->flow_tx_byte_count,
				  sync->return_rx_packet_count, sync->return_rx_byte_count,
				  to_dev, from_dev,
				  dmac, smac,
				  dst_ip, src_ip,
				  dport, sport, tci, tpid);
		goto done;
	}

	/*
	 * For routed flows both from and to side can be OVS bridge port, if there
	 * is a routed flow between two OVS bridges. (e.g: ovs-br1 and ovs-br2)
	 *
	 * PC1 -----> eth1-ovs-br1--->ovs-br2-eth2----->PC2
	 *
	 */
	if (from_dev) {
		/*
		 * from_dev = eth1
		 * br_dev = ovs-br1
		 */
		br_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_FROM, false);
		if (!br_dev) {
			DEBUG_WARN("%p: from_dev = %s is a OVS bridge port, bridge interface is not found\n",
					aci, from_dev->name);
			goto done;
		}
		/*
		 * Sync the flow direction (eth1 to ovs-br1)
		 */
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_FROM, smac);
		ether_addr_copy(dmac, br_dev->dev_addr);

		sport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM);
		dport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO);

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, dst_ip);

		ecm_classifier_ovs_stats_sync(&flow,
				  sync->return_tx_packet_count, sync->return_tx_byte_count,
				  sync->flow_rx_packet_count, sync->flow_rx_byte_count,
				  from_dev, br_dev,
				  smac, dmac,
				  src_ip, dst_ip,
				  sport, dport, tci, tpid);

		/*
		 * Sync the return direction (ovs-br1 to eth1)
		 * All the flow parameters are reversed.
		 */
		ecm_classifier_ovs_stats_sync(&flow,
				  sync->flow_tx_packet_count, sync->flow_tx_byte_count,
				  sync->return_rx_packet_count, sync->return_rx_byte_count,
				  br_dev, from_dev,
				  dmac, smac,
				  dst_ip, src_ip,
				  dport, sport, tci, tpid);
		dev_put(br_dev);
	}

	if (to_dev) {
		/*
		 * to_dev = eth2
		 * br_dev = ovs-br2
		 */
		br_dev = ecm_classifier_ovs_interface_get_and_ref(ci, ECM_DB_OBJ_DIR_TO, false);
		if (!br_dev) {
			DEBUG_WARN("%p: to_dev = %s is a OVS bridge port, bridge interface is not found\n",
					aci, to_dev->name);
			goto done;
		}

		/*
		 * Sync the flow direction (ovs-br2 to eth2)
		 */
		ether_addr_copy(smac, br_dev->dev_addr);
		ecm_db_connection_node_address_get(ci, ECM_DB_OBJ_DIR_TO, dmac);

		sport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_FROM);
		dport = ecm_db_connection_port_get(ci, ECM_DB_OBJ_DIR_TO);

		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_FROM, src_ip);
		ecm_db_connection_address_get(ci, ECM_DB_OBJ_DIR_TO, dst_ip);

		ecm_classifier_ovs_stats_sync(&flow,
				  sync->return_tx_packet_count, sync->return_tx_byte_count,
				  sync->flow_rx_packet_count, sync->flow_rx_byte_count,
				  br_dev, to_dev,
				  smac, dmac,
				  src_ip, dst_ip,
				  sport, dport, tci, tpid);
		/*
		 * Sync the return direction (eth2 to ovs-br2)
		 * All the flow parameters are reversed.
		 */
		ecm_classifier_ovs_stats_sync(&flow,
				  sync->flow_tx_packet_count, sync->flow_tx_byte_count,
				  sync->return_rx_packet_count, sync->return_rx_byte_count,
				  to_dev, br_dev,
				  dmac, smac,
				  dst_ip, src_ip,
				  dport, sport, tci, tpid);
		dev_put(br_dev);
	}

done:
	ecm_db_connection_deref(ci);

	if (from_dev)
		dev_put(from_dev);
	if (to_dev)
		dev_put(to_dev);
}

/*
 * ecm_classifier_ovs_sync_to_v4()
 *	Front end is pushing accel engine state to us
 */
static void ecm_classifier_ovs_sync_to_v4(struct ecm_classifier_instance *aci, struct ecm_classifier_rule_sync *sync)
{
	/*
	 * Nothing to update.
	 * We only care about flows that are actively being accelerated.
	 */
	if (!(sync->flow_tx_packet_count || sync->return_tx_packet_count)) {
		return;
	}

	/*
	 * Handle only the stats sync. We don't care about the evict or flush syncs.
	 */
	if (sync->reason != ECM_FRONT_END_IPV4_RULE_SYNC_REASON_STATS) {
		return;
	}

	/*
	 * Common sync_to function call.
	 */
	ecm_classifier_ovs_sync_to_stats(aci, sync);
}

/*
 * ecm_classifier_ovs_sync_from_v4()
 *	Front end is retrieving accel engine state from us
 */
static void ecm_classifier_ovs_sync_from_v4(struct ecm_classifier_instance *aci, struct ecm_classifier_rule_create *ecrc)
{
	struct ecm_classifier_ovs_instance *ecvi __attribute__((unused));

	ecvi = (struct ecm_classifier_ovs_instance *)aci;
	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
}

/*
 * ecm_classifier_ovs_sync_to_v6()
 *	Front end is pushing accel engine state to us
 */
static void ecm_classifier_ovs_sync_to_v6(struct ecm_classifier_instance *aci, struct ecm_classifier_rule_sync *sync)
{
	/*
	 * Nothing to update.
	 * We only care about flows that are actively being accelerated.
	 */
	if (!(sync->flow_tx_packet_count || sync->return_tx_packet_count)) {
		return;
	}

	/*
	 * Handle only the stats sync. We don't care about the evict or flush syncs.
	 */
	if (sync->reason != ECM_FRONT_END_IPV6_RULE_SYNC_REASON_STATS) {
		return;
	}

	/*
	 * Common sync_to function call.
	 */
	ecm_classifier_ovs_sync_to_stats(aci, sync);
}

/*
 * ecm_classifier_ovs_sync_from_v6()
 *	Front end is retrieving accel engine state from us
 */
static void ecm_classifier_ovs_sync_from_v6(struct ecm_classifier_instance *aci, struct ecm_classifier_rule_create *ecrc)
{
	struct ecm_classifier_ovs_instance *ecvi __attribute__((unused));

	ecvi = (struct ecm_classifier_ovs_instance *)aci;
	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);
}

#ifdef ECM_STATE_OUTPUT_ENABLE
/*
 * ecm_classifier_ovs_state_get()
 *	Gets the state of this classfier and outputs it to debugfs.
 */
static int ecm_classifier_ovs_state_get(struct ecm_classifier_instance *ci, struct ecm_state_file_instance *sfi)
{
	int result;
	struct ecm_classifier_ovs_instance *ecvi;
	struct ecm_classifier_process_response process_response;

	ecvi = (struct ecm_classifier_ovs_instance *)ci;
	DEBUG_CHECK_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC, "%p: magic failed", ecvi);

	if ((result = ecm_state_prefix_add(sfi, "ovs"))) {
		return result;
	}

	spin_lock_bh(&ecm_classifier_ovs_lock);
	process_response = ecvi->process_response;
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	/*
	 * Output our last process response
	 */
	if ((result = ecm_classifier_process_response_state_get(sfi, &process_response))) {
		return result;
	}

	return ecm_state_prefix_remove(sfi);
}
#endif

/*
 * ecm_classifier_ovs_instance_alloc()
 *	Allocate an instance of the ovs classifier
 */
struct ecm_classifier_ovs_instance *ecm_classifier_ovs_instance_alloc(struct ecm_db_connection_instance *ci)
{
	struct ecm_classifier_ovs_instance *ecvi;

	/*
	 * Allocate the instance
	 */
	ecvi = (struct ecm_classifier_ovs_instance *)kzalloc(sizeof(struct ecm_classifier_ovs_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!ecvi) {
		DEBUG_WARN("i%p: Failed to allocate ovs Classifier instance\n", ci);
		return NULL;
	}

	DEBUG_SET_MAGIC(ecvi, ECM_CLASSIFIER_OVS_INSTANCE_MAGIC);
	ecvi->refs = 1;

	/*
	 * Methods generic to all classifiers.
	 */
	ecvi->base.process = ecm_classifier_ovs_process;
	ecvi->base.sync_from_v4 = ecm_classifier_ovs_sync_from_v4;
	ecvi->base.sync_to_v4 = ecm_classifier_ovs_sync_to_v4;
	ecvi->base.sync_from_v6 = ecm_classifier_ovs_sync_from_v6;
	ecvi->base.sync_to_v6 = ecm_classifier_ovs_sync_to_v6;
	ecvi->base.type_get = ecm_classifier_ovs_type_get;
	ecvi->base.reclassify_allowed = ecm_classifier_ovs_reclassify_allowed;
	ecvi->base.reclassify = ecm_classifier_ovs_reclassify;
	ecvi->base.last_process_response_get = ecm_classifier_ovs_last_process_response_get;
#ifdef ECM_STATE_OUTPUT_ENABLE
	ecvi->base.state_get = ecm_classifier_ovs_state_get;
#endif
	ecvi->base.ref = ecm_classifier_ovs_ref;
	ecvi->base.deref = ecm_classifier_ovs_deref;
	ecvi->ci_serial = ecm_db_connection_serial_get(ci);

	ecvi->process_response.process_actions = 0;
	ecvi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_MAYBE;

	/*
	 * Final check if we are pending termination
	 */
	spin_lock_bh(&ecm_classifier_ovs_lock);
	if (ecm_classifier_ovs_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_ovs_lock);
		DEBUG_WARN("%p: Terminating\n", ci);
		kfree(ecvi);
		return NULL;
	}

	/*
	 * Link the new instance into our list at the head
	 */
	ecvi->next = ecm_classifier_ovs_instances;
	if (ecm_classifier_ovs_instances) {
		ecm_classifier_ovs_instances->prev = ecvi;
	}
	ecm_classifier_ovs_instances = ecvi;

	/*
	 * Increment stats
	 */
	ecm_classifier_ovs_count++;
	DEBUG_ASSERT(ecm_classifier_ovs_count > 0, "%p: ecm_classifier_ovs_count wrap for instance: %p\n", ci, ecvi);
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	DEBUG_INFO("%p: ovs classifier instance alloc: %p\n", ci, ecvi);
	return ecvi;
}
EXPORT_SYMBOL(ecm_classifier_ovs_instance_alloc);

/*
 * ecm_classifier_ovs_register_callbacks()
 */
int ecm_classifier_ovs_register_callbacks(struct ecm_classifier_ovs_callbacks *ovs_cbs)
{
	spin_lock_bh(&ecm_classifier_ovs_lock);

	if (unlikely(!ecm_classifier_ovs_enabled)) {
		spin_unlock_bh(&ecm_classifier_ovs_lock);
		return -1;
	}

	ovs.ovs_process = ovs_cbs->ovs_process;
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	return 0;
}
EXPORT_SYMBOL(ecm_classifier_ovs_register_callbacks);

/*
 * ecm_classifier_ovs_unregister_callbacks()
 */
void ecm_classifier_ovs_unregister_callbacks(void)
{
	spin_lock_bh(&ecm_classifier_ovs_lock);
	ovs.ovs_process = NULL;
	spin_unlock_bh(&ecm_classifier_ovs_lock);
}
EXPORT_SYMBOL(ecm_classifier_ovs_unregister_callbacks);

/*
 * ecm_classifier_ovs_init()
 */
int ecm_classifier_ovs_init(struct dentry *dentry)
{
	DEBUG_INFO("ovs classifier Module init\n");

	ecm_classifier_ovs_dentry = debugfs_create_dir("ecm_classifier_ovs", dentry);
	if (!ecm_classifier_ovs_dentry) {
		DEBUG_ERROR("Failed to create ecm ovs directory in debugfs\n");
		return -1;
	}

	if (!debugfs_create_u32("enabled", S_IRUGO | S_IWUSR, ecm_classifier_ovs_dentry,
					(u32 *)&ecm_classifier_ovs_enabled)) {
		DEBUG_ERROR("Failed to create ovs enabled file in debugfs\n");
		debugfs_remove_recursive(ecm_classifier_ovs_dentry);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(ecm_classifier_ovs_init);

/*
 * ecm_classifier_ovs_exit()
 */
void ecm_classifier_ovs_exit(void)
{
	DEBUG_INFO("ovs classifier Module exit\n");

	spin_lock_bh(&ecm_classifier_ovs_lock);
	ecm_classifier_ovs_terminate_pending = true;
	spin_unlock_bh(&ecm_classifier_ovs_lock);

	/*
	 * Remove the debugfs files recursively.
	 */
	if (ecm_classifier_ovs_dentry) {
		debugfs_remove_recursive(ecm_classifier_ovs_dentry);
	}

}
EXPORT_SYMBOL(ecm_classifier_ovs_exit);
