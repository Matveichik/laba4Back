package com.test4.test4.area;

import com.test4.test4.orm.Result;

import java.io.Serializable;

public class PointData implements Serializable {

    float x;
    float y;
    float r;
//    Result point;
    int pointId;
//    String popalText;
    boolean inside;


    public PointData(float x, float y, float r, boolean inside,int pointId) {
        this.x = x;
        this.y = y;
        this.r = r;
        this.pointId=pointId;
        this.inside =inside;
//        this.popalText=Boolean.toString(inside);
//        this.inside =Boolean.toString(inside);
    }

    public int getPointId() {
        return pointId;
    }

    public void setPointId(int pointId) {
        this.pointId = pointId;
    }

    public float getX() {
        return x;
    }

    public void setX(float x) {
        this.x = x;
    }

    public float getY() {
        return y;
    }

    public void setY(float y) {
        this.y = y;
    }

    public float getR() {
        return r;
    }

    public void setR(float r) {
        this.r = r;
    }

    public boolean isInside() {
        return inside;
//        return Boolean.getBoolean(inside);
    }

    public void setInside(boolean inside) {
//        this.inside = Boolean.toString(inside);
        this.inside = inside;
    }


//    public Result getPoint() {
//        return point;
//    }
//
//    public void setPoint(Result point) {
//        this.point = point;
//    }

    @Override
    public String toString() {
        return "PointData{" +
                "x=" + x +
                ", y=" + y +
                ", r=" + r +

                ", inside=" + inside +
                '}';
    }
}
