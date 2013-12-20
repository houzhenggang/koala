package hello;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * User: ya_feng_li@163.com Date: 13-10-22 Time: 上午10:37
 */
public class Greeting {
	@JsonIgnore private final long id;
	private final String content;
	
	public Greeting(long id, String content) {
		this.id = id;
		this.content = content;
	}

	public long getId() {
		return id;
	}

	public String getContent() {
		return content;
	}
}
