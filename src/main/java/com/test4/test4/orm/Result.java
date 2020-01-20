package com.test4.test4.orm;

import javax.persistence.*;
import java.io.Serializable;
import com.test4.test4.area.PointData;

@Entity
@Table(name = "result")
public class Result implements Serializable {
    @Column(name = "x")
    private float x;
    @Column(name = "y")
    private float y;


    @ManyToOne
    private User user;

    @Id
    @SequenceGenerator(name="webuser_idwebuser_seq",
            sequenceName="webuser_idwebuser_seq",
            allocationSize=1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
            generator="webuser_idwebuser_seq")
    @Column(name = "point_id")
    private int point_id;


    public int getPoint_id() {
        return point_id;
    }

    public void setPoint_id(int point_id) {
        this.point_id = point_id;
    }

    public Result(float x, float y, User user) {
        this.x = x;
        this.y = y;
        this.user=user;

    }


    public Result() {
    }

    public float getX() {
        return x;
    }

    public float getY() {
        return y;
    }




    public void setX(float x) {
        this.x = x;
    }

    public void setY(float y) {
        this.y = y;
    }



}
