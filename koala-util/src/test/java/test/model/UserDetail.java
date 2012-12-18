package test.model;

import org.hibernate.annotations.Index;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "TEST_EX_USER_DETAIL")
public class UserDetail {
	@Id
	@SequenceGenerator(name = "udSeq", sequenceName = "TEST_EX_USER_DETIAL_ID")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "udSeq")
	private Long id;
	@Basic
	@Column(name = "username", length = 50, unique = true, nullable = false)
	private String username;
	@Basic
	@Column(name = "address", length = 200, unique = false, nullable = false)
	private String address;
	@Basic
	@Column(name = "birthday", nullable = false)
	@Index(name = "INDEX_BIRTHDAY")
	private Date birthday;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public Date getBirthday() {
		return birthday;
	}

	public void setBirthday(Date birthday) {
		this.birthday = birthday;
	}
}
