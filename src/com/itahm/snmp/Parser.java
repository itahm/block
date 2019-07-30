package com.itahm.snmp;

import java.util.HashMap;
import java.util.Map;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

abstract public class Parser<T> implements Parsable {
	
	private final OID request;
	private final Map<Integer, T> value = new HashMap<>();
	private Map<Integer, Map<Long, T>> rolling;
	private final boolean callback;
	
	public Parser (OID request, boolean rolling, boolean callback) {
		this.request = request;
		this.callback = callback;
		
		if (rolling) {
			this.rolling = new HashMap<>();
		}
	}
	
	public Parser (OID request) {
		this(request, false, false);
	}
	
	@Override
	public boolean parse(OID response, Variable variable) {
		if (response.startsWith(this.request)) {
			int index = response.last();
			
			parse(index, variable);
			
			if (index > 0) {
				return true;
			}
		}
		
		return false;
	}

	private void parse(int index, Variable variable) {
		T
			value = valueOf(variable),
			old = this.value.put(index, value);
	
		if (this.rolling != null) {
			Map<Long, T> map = this.rolling.get(index);
			
			if (map == null) {
				map = new HashMap<>();
				
				this.rolling.put(index, map);
			}
			
			map.put(System.currentTimeMillis(), value);
		}
	
		if (this.callback && old != null && !old.equals(value)) {
			// TODO callback
		}
	}
	
	abstract protected T valueOf(Variable variable);
	
}
