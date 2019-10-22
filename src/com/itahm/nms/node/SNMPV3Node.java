package com.itahm.nms.node;
import java.io.IOException;
import java.net.InetAddress;

import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;

public class SNMPV3Node extends SNMPNode {

	public SNMPV3Node(Snmp snmp, long id, String ip, int udp, String user, int level)
			throws IOException {
		super(snmp, id, ip, new UserTarget<UdpAddress>(new UdpAddress(InetAddress.getByName(ip), udp), new OctetString(user), new byte [0], level));
		
		super.target.setVersion(SnmpConstants.version3);
	}
	
	@Override
	public PDU createPDU() {
		PDU pdu = new ScopedPDU();
		
		pdu.setType(PDU.GETNEXT);
		
		return pdu;
	}
	
}
