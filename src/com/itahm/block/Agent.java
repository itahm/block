package com.itahm.block;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

import com.itahm.block.node.SeedNode.Protocol;

public interface Agent {
	public void informPingEvent(long id, long rtt, String protocol);
	public void informSNMPEvent(long id, int code);
	public void informResourceEvent(long id, OID oid, OID index, Variable variable);
	public void informTestEvent(long id, String ip, Protocol protocol, Object result);
}
