package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

import java.util.HashMap;

public class HRProcessorLoad extends AbstractParser {
	private final Map<Long, Map<Integer, Integer>> load = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.25.3.3.1.2");
		
		if (v == null) {
			return null;
		}
		
		int
			index,
			load;
		
		try {
			index = Integer.valueOf(idx);
		} catch (NumberFormatException nfe) {
			return null;
		}
		
		try {
			load = Integer.valueOf(v.value);
		} catch (NumberFormatException nfe) {
			return null;
		}
		
		Map<Integer, Integer> indexMap = this.load.get(id);
			
		if (indexMap == null) {
			this.load.put(id, indexMap = new HashMap<>());
		}
		
		indexMap.put(index, load);
		
		Max max = super.max.get(id);
		
		if (max == null || max.rate < load) {
			super.max.put(id, new Max(id, index, load, load));
		}
			
		return null;
	}

	public CriticalEvent parse(long id, int load, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.4.1.49447.4");
		
		if (v == null) {
			return null;
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
		
		return count > 0? sum / count: null;
	}
	
	@Override
	public String toString() {
		return "HRPROCESSORLOAD";
	}

}
