package test.model;

import javax.persistence.*;

import java.io.Serializable;

@Entity
@Table(name = "TEST_I_USER")
public class IUser implements Serializable {

    @Id
    @SequenceGenerator(name = "userSeq", sequenceName = "TEST_IUSER_SEQ")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "userSeq")
    private Integer id;
    @Column(unique = true)
    protected String username;
    protected String password;
    protected String age;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAge() {
        return age;
    }

    public void setAge(String age) {
        this.age = age;
    }
}
