package com.test4.test4.controller;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.test4.test4.area.AreaCheck;
import com.test4.test4.area.PointData;
import com.test4.test4.orm.ResultRs;
import com.test4.test4.orm.User;
import com.test4.test4.services.PointsDataService;
import com.test4.test4.services.UserDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/point")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials="true")
public class PointController {


    @Autowired
    UserDataService userDataService;

    @Autowired
    PointsDataService pointsDataService;
   @PostMapping(value = "/addNewResult"  ,produces = "application/json; charset=utf-8")
    public String addNewResult(HttpServletResponse response, HttpSession httpSession, @RequestBody addNewResultRequestBody body) {

        response.addHeader("Content-type", "application/json;charset=UTF-8");

      if(!isValider((float)body.getR())){

          return "{ \"success\":" + false + ",\"why\":\""+whyValider((float)body.getR())+ "\"}";
      };

       ResultRs rs= pointsDataService.AddNewResult( (float)body.getX(),(float)body.getY(),(float)body.getR(),
                userDataService.GetUserByLogin((String) httpSession.getAttribute("login")));


        Gson gson=new Gson();


        return  gson.toJson(new addNewResultResponseBody(true,rs.isInside(),rs.getPoint().getPoint_id()));
    }



    @GetMapping(value ="/deleteActualPoint/{point_id}")
    public String deleteActualPoint(HttpSession httpSession, @PathVariable int point_id) {




        pointsDataService.deleteActualPoint(point_id);

        return "{ \"success\":" + true + "}";

        }

    @GetMapping(value ="/reDrawActualPoint/{point_id}/{radius}",produces = "application/json; charset=utf-8")
    public String reDrawPointActualPoint(HttpSession httpSession, @PathVariable int point_id,@PathVariable float radius) {

        if(!isValider(radius)){

            return "{ \"success\":" + false + ",\"why\":\""+whyValider(radius)+ "\"}";
        };





        return "{ \"success\":" + pointsDataService.reDrawActualPoint(point_id,radius) + "}";

        }


    @GetMapping(value ="/allActualResults/{RadiusForCanvas}",produces = "application/json; charset=utf-8")
    public String allActualResults(HttpSession httpSession,@PathVariable double RadiusForCanvas) {

        if(!isValider((float) RadiusForCanvas)){

            return "{ \"success\":" + false + ",\"why\":\""+whyValider((float) RadiusForCanvas)+ "\"}";
        };



        System.out.println("/allActualResults");
        System.out.println((String) httpSession.getAttribute("login"));

        Gson gson=new Gson();

        List<PointData> Actualresults=pointsDataService.GetAll((String) httpSession.getAttribute("login"));
        List<PointData>Canvasresults=new ArrayList<>();


        Actualresults.forEach(pointData ->{

            Canvasresults.add(new PointData(pointData.getX(),
                    pointData.getY(),
                    (float)RadiusForCanvas,
                    new AreaCheck().match(pointData.getX(),pointData.getY(),(float)RadiusForCanvas),
                    pointData.getPointId()));

        });

        return  gson.toJson(new ResultsResponse(true,Actualresults,Canvasresults   ));


    }


    @GetMapping("/allActualResults1/")
    public String allActualResultsWithRadius(HttpSession httpSession) {




        System.out.println("/allActualResults");
        System.out.println((String) httpSession.getAttribute("login"));

        Gson gson=new Gson();

        return  gson.toJson(new ResultsResponse(true,pointsDataService.GetAll((String) httpSession.getAttribute("login"))));
    }

public boolean isValidexyr(float x,float y,float r){

    AreaCheck areaCheck = new AreaCheck();
    return areaCheck.valid(x,y,r);
}
public boolean isValider(float r){

    AreaCheck areaCheck = new AreaCheck();
    return areaCheck.matchR(r);
}
public String whyValidexyr(float x,float y,float r){

    AreaCheck areaCheck = new AreaCheck();
    return areaCheck.validWhy(x,y,r);
}
public String whyValider(float r){

    AreaCheck areaCheck = new AreaCheck();
    return areaCheck.validWhyR(r);
}


}
class ResultsResponse implements Serializable{
    boolean success;
    List<PointData> ActualResults;
    List<PointData> CanvasResults;

    public ResultsResponse(boolean success, List<PointData> ActualResults, List<PointData> CanvasResults) {
        this.success = success;
        this.ActualResults = ActualResults;
        this.CanvasResults = CanvasResults;
    }

    public ResultsResponse(boolean success, List<PointData> actualResults) {
        this.success = success;
        ActualResults = actualResults;
    }
}


class addNewResultResponseBody implements Serializable {
    boolean success;
    boolean inside;
    int point_id;
    public addNewResultResponseBody(boolean success, boolean inside,int point_id) {
        this.success = success;
        this.inside = inside;
        this.point_id = point_id;
    }
}
class addNewResultRequestBody implements Serializable {
    double x;
    double y;
    double r;


    public addNewResultRequestBody() {
    }

    public addNewResultRequestBody(double x, double y, double r) {
        this.x = x;
        this.y = y;
        this.r = r;

    }

    public double getX() {
        return x;
    }

    public void setX(double x) {
        this.x = x;
    }

    public double getY() {
        return y;
    }

    public void setY(double y) {
        this.y = y;
    }

    public double getR() {
        return r;
    }

    public void setR(double r) {
        this.r = r;
    }
}

