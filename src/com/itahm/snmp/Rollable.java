package com.itahm.snmp;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

public interface Rollable {
	public boolean role(OID response, Variable variable);
}
