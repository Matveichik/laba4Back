package com.test4.test4.repositories;

import com.test4.test4.area.PointData;
import com.test4.test4.orm.Result;
import com.test4.test4.orm.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResultRepository extends JpaRepository<Result, Integer> {

    @Query("SELECT NEW com.test4.test4.area.PointData(point.x,point.y,rez.r,rez.inside,point.point_id) " +
            "FROM ResultActual act, ResultRs rez, Result point, User user" +
            " where " +
            "point.user = user " +
            "and user.login=?1 " +
            "and rez.point=point " +
            "and act.history_point=rez order by point.point_id asc ")
    List<PointData> GetAll(String login);



}
