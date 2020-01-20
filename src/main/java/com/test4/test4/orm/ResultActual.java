package com.test4.test4.orm;

import javax.persistence.*;

@Entity
@Table(name = "actual_result")
public class ResultActual
{

    @Id
    @SequenceGenerator(name="ResultActual_idwebuser_seq",
            sequenceName="ResultActual_idwebuser_seq",
            allocationSize=1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
            generator="ResultActual_idwebuser_seq")
    @Column(name = "ActualPoint_id",table ="actual_result" )
    private int ActualPoint_id;

   // @Column(name = "history_point")
    //@JoinColumn(name="id")
    @OneToOne(orphanRemoval = false)
    private ResultRs history_point;


    public ResultActual(ResultRs history_point) {
        this.history_point = history_point;
    }

    public ResultActual() {
    }

    public int getActualPoint_id() {
        return ActualPoint_id;
    }

    public void setActualPoint_id(int actualPoint_id) {
        ActualPoint_id = actualPoint_id;
    }

}
