package com.test4.test4.orm;



import com.test4.test4.area.AreaCheck;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "resultrs")
public class ResultRs {




    @Id
    @SequenceGenerator(name="resrs_seq",
            sequenceName="resrs_seq",
            allocationSize=1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
            generator="resrs_seq")
    @Column(name = "id")
    private int id;

    @ManyToOne
    private Result point;

    @Column(name = "r")
    private float r;

    @Column(name = "date")
    private Date date;


    @Column(name = "inside")
    private boolean inside;

    public boolean isInside() {
        return inside;
    }

    public void setInside(boolean inside) {
        this.inside = inside;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }



    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }


    public ResultRs() {
    }

    public ResultRs( float r, Date date) {
        this.r = r;
        this.date = date;
    }


    public ResultRs(Result point, float r, Date date) {

        this.point = point;
        this.r = r;
        this.date = date;
        AreaCheck areaCheck=new AreaCheck();
        this.inside= areaCheck.match(point.getX(),point.getY(),r);

    }

    public Result getPoint() {
        return point;
    }

    public void setPoint(Result point) {
        this.point = point;
    }
}
