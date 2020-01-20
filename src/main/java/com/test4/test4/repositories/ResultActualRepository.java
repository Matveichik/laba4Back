package com.test4.test4.repositories;

import com.test4.test4.orm.Result;
import com.test4.test4.orm.ResultActual;
import com.test4.test4.orm.ResultRs;
import com.test4.test4.orm.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository @Component
public interface ResultActualRepository extends JpaRepository<ResultActual, Long> {
    @Transactional
    @Modifying
    @Query("UPDATE ResultActual c SET c.history_point = ?1 " +
            "where c in " +
            "(select act2 FROM ResultActual act2  WHERE act2.history_point.point.point_id=?2) ")
    void changeActualPoint(ResultRs newHistoryPoint,int curPointId);

    @Transactional
    @Modifying
    @Query("DELETE FROM ResultActual act " +
            "WHERE act in " +
            "(select act2 FROM ResultActual act2  WHERE act2.history_point.point.point_id=?1)")
    void deleteActualPoint(int curPointId);



}
