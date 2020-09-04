package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.Counter;
import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

public class IFOutOctets extends AbstractParser2 {
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		long speed = 0;
		Value v = oidMap.get("1.3.6.1.4.1.49447.3.5");
		
		if (v == null) {
			v = oidMap.get("1.3.6.1.2.1.31.1.1.1.15");
			
			if (v == null) {
				v = oidMap.get("1.3.6.1.2.1.2.2.1.5");
				
				if (v == null) {
					return null;
				} else {
					speed = Long.valueOf(v.value);		
				}
			} else {
				speed = Long.valueOf(v.value) *1000000L;	
			}
		} else {
			speed = Long.valueOf(v.value);
		}
		
		if (speed <= 0) {
			return null;
		}
		v = oidMap.get("1.3.6.1.2.1.31.1.1.1.10");
		
		if (v == null) {
			v = oidMap.get("1.3.6.1.2.1.2.2.1.16");
		}

		if (v == null || !(v instanceof Counter)) {
			return null;
		}
		
		int index;
						
		try {
			index = Integer.valueOf(idx);
		} catch (NumberFormatException nfe) {
			return null;
		}
				
		Long bps = ((Counter)v).counter();
		
		if (bps == null) {
			return null;
		}
		
		bps *= 8;
		
		Max max = this.max.get(id);
		Value bpsValue = oidMap.get("1.3.6.1.4.1.49447.3.2");
		
		if (max == null || max.value < bps) {
			this.max.put(id, new Max(id, index, bps, bps *100 / speed));
		}
		
		max = this.maxRate.get(id);
		
		if (max == null || max.rate < bps *100 / speed) {
			this.maxRate.put(id, new Max(id, index, bps, bps *100 / speed));
		}
		
		if (bpsValue == null) {
			bpsValue = new Value();
			
			oidMap.put("1.3.6.1.4.1.49447.3.2", bpsValue);
		} 
		
		bpsValue.set(v.timestamp, Long.toString(bps));
		
		if (v.limit > 0) {
			boolean critical = bps *100 / speed > v.limit;
		
			if (v.critical != critical) {
				v.critical = critical;
				
				return new CriticalEvent(id, idx, "1.3.6.1.2.1.2.2.1.16", critical,
					String.format("송신 %d%%", bps *100 / speed));
			}
		} else if (v.critical) {
			v.critical = false;
			
			return new CriticalEvent(id, idx, "1.3.6.1.2.1.2.2.1.16", false,
				String.format("송신 %d%%", bps *100 / speed));
		}
		
		return null;
	}
	
	@Override
	public String toString() {
		return "IFOUTOCTETS";
	}
}
