package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

abstract public class HRStorage extends AbstractParser2 {
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.25.2.3.1.2"); // type
		
		if (v != null) {
			if (v.value.equals(getStorageTypeOID())) { // fixed disk
		
				v = oidMap.get("1.3.6.1.2.1.25.2.3.1.5"); // syze
				
				if (v != null) {
					long size = Long.valueOf(v.value);
					
					v = oidMap.get("1.3.6.1.2.1.25.2.3.1.4"); // units
					
					if (v != null) {
						long units = Long.valueOf(v.value);
						
						v = oidMap.get("1.3.6.1.2.1.25.2.3.1.6"); // used
		
						if (v != null) {
							int index;
							
							try {
								index = Integer.valueOf(idx);
							} catch (NumberFormatException nfe) {
								return null;
							}
							
							long used = Long.valueOf(v.value);
							Max max = this.max.get(id);
							
							if (max == null || max.value < used * units) {
								this.max.put(id, new Max(id, index, used * units, used *100 / size));
							}
							
							max = this.maxRate.get(id);
							
							if (max == null || max.rate < used *100 / size) {
								this.maxRate.put(id, new Max(id, index, used * units, used *100 / size));
							}
							
							if (v.limit > 0) {
								boolean critical = used *100 / size > v.limit;
								
								if (critical != v.critical) {
									v.critical = critical;
									
									return new CriticalEvent(id, idx, "1.3.6.1.2.1.25.2.3.1.6",
										critical, String.format("%s %d%%", getEventTitle(), used *100 / size));
								}
							} else if (v.critical) {
								v.critical = false;
								
								return new CriticalEvent(id, idx, "1.3.6.1.2.1.25.2.3.1.6",
									false, String.format("%s %d%%", getEventTitle(), used *100 / size));
							}
						}
					}
				}
			}
		}
		
		return null;
	}
	
	abstract public String getStorageTypeOID();
	abstract protected String getEventTitle();
}
