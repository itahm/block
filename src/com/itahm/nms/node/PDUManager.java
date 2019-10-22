package com.itahm.nms.node;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.snmp4j.PDU;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

public class PDUManager {
	private static OID [] common = new OID [0];
	private static Map<Long, OID[]> idMap = new HashMap<>();
	
	public static void setPDU(Set<String> oids) {
		common = parseOIDS(oids);
	}
	
	public static void setPDU(long id, Set<String> oids) {
		idMap.put(id, parseOIDS(oids));
	}
	
	private static OID [] parseOIDS(Set<String> oids) {
		OID [] arr = new OID [oids.size()];
		int i = 0;
		
		for (String oid : oids) {
			arr[i++] = new OID(oid);
		}
		
		return arr;
	}
	public static PDU requestPDU(long id, PDU pdu) {
		VariableBinding [] vbs = VariableBinding.createFromOIDs(common);
		OID [] arr = idMap.get(id);
		
		for (VariableBinding vb : vbs) {
			pdu.add(vb);
		}
		
		if (arr != null) {
			vbs = VariableBinding.createFromOIDs(arr);
			
			for (VariableBinding vb : vbs) {
				pdu.add(vb);
			}
		}
		
		return pdu;
	}
}
