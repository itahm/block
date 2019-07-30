package com.itahm.snmp;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

public interface Parsable {
	public boolean parse(OID response, Variable variable);
}
