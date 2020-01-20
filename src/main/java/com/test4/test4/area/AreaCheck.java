package com.test4.test4.area;

public class AreaCheck {
    private static final double[] possibleX = {-3, -2, -1,  0, 1, 2, 3, 4, 5};
    private static final double[] possibleR = {0, 1, 2, 3, 4, 5};
    private static final double minY = -5;
    private static final double maxY = 5;


    public boolean valid(double x, double y, double r) {
        return matchX(x) &&
                y >= minY && y <= maxY &&
                matchR(r);
    }

    public String validWhy(double x, double y, double r) {
       StringBuilder why=new StringBuilder();
        if(!matchX(x)){
            why.append("X не валиден");
        }

        if(! (y >= minY && y <= maxY)){
            why.append("Y не валиден");
        }


            why.append("X не валиден").append(validWhyR(r));

        return why.toString();
        }

    public String validWhyR(double r) {
        StringBuilder why = new StringBuilder();

        if(r<0) why.append("R меньше нуля не валиден!");

    return why.toString();
    }


    private boolean matchX(double x) {
        for (double aPossibleX : possibleX)
            if (x == aPossibleX)
                return true;
        return false;
    }
    public boolean matchR(double r) {
        for (double aPossibleR : possibleR)
            if (r == aPossibleR)
                return true;
        return false;
    }
    public boolean match(double x, double y, double r) {
        return arcMatch(x, y, r) || rectMatch(x, y, r) || triMatch(x, y, r);
    }
    private boolean arcMatch(double x, double y, double r){
        return  x >= 0 && y <= 0 && x*x + y*y <= r*r;

    }

    private boolean rectMatch(double x, double y, double r){

       return x <=0 && y >= 0 && Math.abs(x) <= (r) && y <= r;

    }
    private boolean triMatch(double x, double y, double r){

        return x <= 0 && y <= 0 &&  y>=-2*x-r;

    }

}
