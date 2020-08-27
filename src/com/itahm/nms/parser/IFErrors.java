package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.Counter;
import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

abstract public class IFErrors extends AbstractParser {
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get(getErrorsOID());
		
		if (v != null && v instanceof Counter) {
			int index;
			
			try {
				index = Integer.valueOf(idx);
			} catch (NumberFormatException nfe) {
				return null;
			}
			
			Long cps = ((Counter)v).counter();
			
			if (cps != null) {
				Max max = this.max.get(id);
				Value cpsValue = oidMap.get(getCPSOID());
				
				if (max == null || Long.valueOf(max.value) < cps) {
					this.max.put(id, new Max(id, index, Long.toString(cps)));
				}
				
				if (cpsValue == null) {
					cpsValue = new Value();
					
					oidMap.put(getCPSOID(), cpsValue);
				}
				
				cpsValue.set(v.timestamp, Long.toString(cps));
				
				if (v.limit > 0) {
					boolean critical = cps > v.limit;
				
					if (v.critical != critical) {
						v.critical = critical;
						
						return new CriticalEvent(id, idx, getErrorsOID(), critical, String.format("%s %dcps", getEventTitle(), cps));
					}
				} else if (v.critical) {
					v.critical = false;
					
					return new CriticalEvent(id, idx, getErrorsOID(), false, String.format("%s %dcps", getEventTitle(), cps));
				}
			}
		}
		
		return null;
	}

	abstract protected String getErrorsOID();
	abstract protected String getCPSOID();
	abstract protected String getEventTitle();
	
}
