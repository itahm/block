package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.CriticalEvent;
import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.HashMap;

public class HRProcessorLoad extends AbstractParser {
	private final Map<Long, Map<Integer, Integer>> load = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.25.3.3.1.2");
		
		if (v != null) {
			int
				index = Integer.valueOf(idx),
				load = Integer.valueOf(v.value);
			
			Map<Integer, Integer> indexMap = this.load.get(id);
				
			if (indexMap == null) {
				this.load.put(id, indexMap = new HashMap<>());
			}
			
			indexMap.put(index, load);
			
			Max max = super.max.get(id);
			
			if (max == null || Integer.valueOf(max.value) < load) {
				super.max.put(id, new Max(id, index, Integer.toString(load), load));
			}
			
			if (v.limit > 0) {
				boolean critical = load > v.limit;
				
				if (critical != v.critical) {
					v.critical = critical;
					
					return new CriticalEvent(id, "0", "1.3.6.1.2.1.25.3.3.1.2", critical, String.format("프로세서 로드 %d%%", load));
				}
			} else if (v.critical) {
				v.critical = false;
					
				return new CriticalEvent(id, "0", "1.3.6.1.2.1.25.3.3.1.2", false, String.format("프로세서 로드 %d%%", load));
			}
		}
			
		return null;
	}

	public Integer getLoad(long id) {
		int sum = 0;
		int count = 0;
		
		Map<Integer, Integer> indexMap = this.load.get(id);
		
		if (indexMap == null) {
			return null;
		}
		
		for (int index : indexMap.keySet()) {
			sum += indexMap.get(index);
			
			count++;
		}
		
		return sum / count;
	}

}
