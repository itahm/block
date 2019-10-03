package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.CriticalEvent;
import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.HashMap;

public class ResponseTime extends AbstractParser {
	private final Map<Long, Map<Integer, Long>> rtt = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		int index = Integer.valueOf(idx);
		Value v = oidMap.get("1.3.6.1.4.1.49447.1");
		
		if (v != null) {
			Long rtt = Long.valueOf(v.value);
			Map<Integer, Long> indexMap = this.rtt.get(id);
				
			if (indexMap == null) {
				this.rtt.put(id, indexMap = new HashMap<>());
			}
			
			indexMap.put(index, rtt);
			
			Max max = super.max.get(id);
			
			if (max == null || Long.valueOf(max.value) < rtt) {
				super.max.put(id, new Max(id, index, Long.toString(rtt)));
			}
			
			if (v.limit > 0) {
				boolean critical = rtt > v.limit;
			
				if (v.critical != critical) {
					v.critical = critical;
					
					return new CriticalEvent(id, "0", "1.3.6.1.4.1.49447.1", critical,
						String.format("응답 시간 %dms", rtt));
				}
			} else if (v.critical) {
				v.critical = false;
				
				return new CriticalEvent(id, "0", "1.3.6.1.4.1.49447.1", false,
					String.format("응답 시간 %dms", rtt));
			}
		}
		
		return null;
	}

}
