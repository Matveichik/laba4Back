package com.test4.test4.services;

import com.test4.test4.orm.User;
import com.test4.test4.repositories.UserRepository;
import jdk.nashorn.internal.ir.debug.JSONWriter;
import jdk.nashorn.internal.parser.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDataService {

    @Transactional
    public void PutUser(User user){

        userRepository.save(user);

    }

    @Autowired
    private UserRepository userRepository;

    @Transactional
    public User GetUserByLogin(String login) {

        //User user = userRepository.FindUser(login);
        User user1 = userRepository.findBylogin(login);
        return user1;

    }
}
