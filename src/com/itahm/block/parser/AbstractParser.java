package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.Max;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

abstract public class AbstractParser implements Parseable {
	
	protected Map<Long, Max> publicMax = new HashMap<>();
	protected Map<Long, Max> max = new HashMap<>();

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

}
