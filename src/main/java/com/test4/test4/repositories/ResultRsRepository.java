package com.test4.test4.repositories;

import com.test4.test4.orm.Result;
import com.test4.test4.orm.ResultActual;
import com.test4.test4.orm.ResultRs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

@Repository @Component
public interface ResultRsRepository extends JpaRepository<ResultRs, Long> {



}
