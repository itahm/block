package com.itahm.snmp;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;

public class StringParser extends Parser<String> {
	
	public StringParser(OID request, boolean rolling, boolean callback) {
		super(request, rolling, callback);		
	}

	@Override
	protected String valueOf(Variable variable) {
		return new String(((OctetString)variable).getValue());
	}
}
