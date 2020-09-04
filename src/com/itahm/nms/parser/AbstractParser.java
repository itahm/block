package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.Max;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

abstract public class AbstractParser implements Parseable {
	
	protected Map<Long, Max> publicMax = new HashMap<>(); //submit 후 max
	protected Map<Long, Max> max = new HashMap<>(); //submit 이전 max, submit 후 초기화 됨.

	@Override
	public List<Max> getTop(int count, boolean byRate) {
		
		final List<Long> keys = new ArrayList<>(this.publicMax.keySet());
		List<Max> result = new ArrayList<>();
		Max max;
		
		Collections.sort(keys, new Comparator<Long>() {

			@Override
			public int compare(Long id1, Long id2) {
				Max max1 = publicMax.get(id1);
				Max max2 = publicMax.get(id2);
				
				if (max1 == null && max2 == null) {
					return 0;
				}
			
				if (max1 == null) {
					return 1;
				}
				
				if (max2 == null) {
					return -1;
				}
				
				long l = max2.value - max1.value;
				
				return l > 0? 1: l < 0? -1: 0;
			}
		});
		
		for (int i=0, _i=Math.min(keys.size(), count); i<_i; i++) {
			max = publicMax.get(keys.get(i));
			
			if (max != null) {
				result.add(max);
			}
		}
		
		return result;
	}
	
	@Override
	public void submit(long id) {
		Max max = this.max.remove(id);
		
		if (max != null) {
			this.publicMax.put(id, max);
		}
	}
	
	@Override
	public void reset(long id) {
		this.publicMax.remove(id);
	}

}
