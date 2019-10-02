package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.CriticalEvent;
import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.HashMap;

abstract public class IFErrors extends AbstractParser {
	private final Map<Long, Map<Integer, Value>> oldMap = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get(getErrorsOID());
		
		if (v != null) {
			Map<Integer, Value> oldIndexMap = this.oldMap.get(id);
			
			if (oldIndexMap == null) {
				this.oldMap.put(id, oldIndexMap = new HashMap<Integer, Value>());
			}
			
			int index = Integer.valueOf(idx);
			Long cps = parse(id, oldIndexMap.get(index), Long.valueOf(v.value), v.timestamp);
			
			oldIndexMap.put(index, new Value(v.timestamp, v.value));
			
			if (cps != null) {
				Max max = this.max.get(id);
				Value cpsValue = oidMap.get(getCPSOID());
				
				if (max == null || Long.valueOf(max.value) < cps) {
					this.max.put(id, new Max(id, index, Long.toString(cps)));
				}
				
				if (cpsValue == null) {
					oidMap.put(getCPSOID(), new Value(v.timestamp, Long.toString(cps)));
				} else {					
					cpsValue.timestamp = v.timestamp;
					cpsValue.value = Long.toString(cps);
				}
				
				if (v.limit > 0) {
					boolean critical = cps > v.limit;
				
					if (v.critical != critical) {
						v.critical = critical;
						
						return new CriticalEvent(id, idx, getErrorsOID(), critical, getEventTitle());
					}
				}
			}
		}
		
		return null;
	}
	
	private Long parse(long id, Value old, long errors, long timestamp) {
		if (old != null) {
			long diff = timestamp - old.timestamp;
			
			if (diff > 0) {
				return (errors - Long.valueOf(old.value)) / diff *1000;
			}
		}
		
		return null;
	}

	abstract protected String getErrorsOID();
	abstract protected String getCPSOID();
	abstract protected String getEventTitle();
	
}
