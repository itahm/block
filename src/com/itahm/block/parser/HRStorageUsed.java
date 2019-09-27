package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class HRStorageUsed implements Parseable {
	//private final Map<Long, Map<Integer, Long>> usage = new HashMap<>();
	private Map<Long, Max> publicMax = new HashMap<>();
	private Map<Long, Max> max = new HashMap<>();
	private Map<Long, Max> publicMaxRate = new HashMap<>();
	private Map<Long, Max> maxRate = new HashMap<>();
	
	@Override
	public void parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.25.2.3.1.2");
		
		if (v == null) {
			return;
		}
		
		if (!v.value.equals("1.3.6.1.2.1.25.2.1.4")) {
			return;
		}
		
		v = oidMap.get("1.3.6.1.2.1.25.2.3.1.6");
		
		if (v == null) {
			return;
		}
		
		long used = Long.valueOf(v.value);
		
		v = oidMap.get("1.3.6.1.2.1.25.2.3.1.5");
		
		if (v == null) {
			return;
		}
		
		long size = Long.valueOf(v.value);
		
		v = oidMap.get("1.3.6.1.2.1.25.2.3.1.4");
		
		if (v == null) {
			return;
		}
		
		long units = Long.valueOf(v.value);
		int index = Integer.valueOf(idx);
		
		Max max = this.max.get(id);
		
		if (max == null || Long.valueOf(max.value) < used * units) {
			this.max.put(id, new Max(id, index, Long.toString(used * units), used *100 / size));
		}
		
		max = this.maxRate.get(id);
		
		if (max == null || max.rate < used *100 / size) {
			this.maxRate.put(id, new Max(id, index, Long.toString(used * units), used *100 / size));
		}
		
		oidMap.put("1.3.6.1.4.1.49447.4.2", new Value(v.timestamp, Long.toString(used * units)));
	}

	@Override
	public List<Max> getTop(List<Long> list, boolean byRate) {
		List<Max> result = new ArrayList<>();
		
		if (byRate) {
			final Map<Long, Max> idMap = this.publicMaxRate;
			
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
					
					long l = max2.rate - max1.rate;
					
					return l > 0? 1: l < 0? -1: 0;
				}
			});
			
			Max max;
			
			for (int i=0, _i=list.size(); i<_i; i++) {
				max = idMap.get(list.get(i));
				
				if (max != null) {
					result.add(max);
				}
			}
		} else {
			final Map<Long, Max> idMap = this.publicMax;
			
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
					
					long l = Long.valueOf(max2.value) - Long.valueOf(max1.value);
					
					return l > 0? 1: l < 0? -1: 0;
				}
			});
			
			Max max;
			
			for (int i=0, _i=list.size(); i<_i; i++) {
				max = idMap.get(list.get(i));
				
				if (max != null) {
					result.add(max);
				}
			}
		}
		
		return result;
	}
	
	@Override
	public void submit(long id) {
		this.publicMax.put(id, this.max.get(id));
		this.publicMaxRate.put(id, this.maxRate.get(id));
		
		this.max.remove(id);
		this.maxRate.remove(id);
	}
	
	@Override
	public void reset(long id) {
		this.publicMax.remove(id);
		this.publicMaxRate.remove(id);
	}

	@Override
	public String getOID(String oid) {
		return null;
	}

}
