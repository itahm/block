package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class HRProcessorLoad implements Parseable {
	private final Map<Long, Map<Integer, Integer>> load = new HashMap<>();
	private Map<Long, Max> publicMax = new HashMap<>();
	private Map<Long, Max> max = new HashMap<>();
	
	@Override
	public void parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.25.3.3.1.2");
		
		if (v == null) {
			return;
		}
		
		int
			index = Integer.valueOf(idx),
			load = Integer.valueOf(v.value);
		
		Map<Integer, Integer> indexMap = this.load.get(id);
			
		if (indexMap == null) {
			this.load.put(id, indexMap = new HashMap<>());
		}
		
		indexMap.put(index, load);
		
		Max max = this.max.get(id);
		
		if (max == null || Integer.valueOf(max.value) < load) {
			this.max.put(id, new Max(id, index, Integer.toString(load), load));
		}
	}

	@Override
	public List<Max> getTop(List<Long> list, boolean byRate) {
		final Map<Long, Max> idMap = this.publicMax;
		
		List<Max> result = new ArrayList<>();
		
		Collections.sort(list, new Comparator<Long>() {

			@Override
			public int compare(Long id1, Long id2) {
				Max max1 = idMap.get(id1);
				Max max2 = idMap.get(id2);
				
				if (max1 == null) {
					if (max2 == null) {
						return -1;
					}
					else {
						return 1;
					}
				} else if (max2 == null) {
					return -1;
				}
				
				return Integer.valueOf(max2.value) - Integer.valueOf(max1.value);
			}
		});
		
		Max max;
		
		for (int i=0, _i=list.size(); i<_i; i++) {
			max = idMap.get(list.get(i));
			
			if (max != null) {
				result.add(max);
			}
		}
		
		return result;
	}
	
	@Override
	public void submit(long id) {
		this.publicMax.put(id, this.max.get(id));
		
		this.max.remove(id);
	}
	
	@Override
	public void reset(long id) {
		this.publicMax.remove(id);
	}

	@Override
	public String getOID(String oid) {
		switch (oid) {
		case "1.3.6.1.4.1.9.2.1.5.6":
		case "1.3.6.1.4.1.9.9.109.1.1.1.1.3" :
		case "1.3.6.1.4.1.9.9.109.1.1.1.1.6" :
		case "1.3.6.1.4.1.6296.9.1.1.1.8" :
		case "1.3.6.1.4.1.37288.1.1.3.1.1" ://System.out.println(oid);
			return "1.3.6.1.2.1.25.3.3.1.2";
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
