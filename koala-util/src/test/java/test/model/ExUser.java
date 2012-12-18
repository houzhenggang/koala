package test.model;

import javax.persistence.*;


@Entity
public class ExUser extends IUser {

    @Basic
    @Column(name = "exkey", length = 50, nullable = false)
    protected String exkey;
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.REMOVE)
    @JoinColumn(name = "udid", referencedColumnName = "id", unique = true, nullable = false)
    private UserDetail userDetail;

    public String getExkey() {
        return exkey;
    }

    public void setExkey(String exkey) {
        this.exkey = exkey;
    }

    public UserDetail getUserDetail() {
        return userDetail;
    }

    public void setUserDetail(UserDetail userDetail) {
        this.userDetail = userDetail;
    }
}
