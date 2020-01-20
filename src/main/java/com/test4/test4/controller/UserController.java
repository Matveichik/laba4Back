package com.test4.test4.controller;

import com.test4.test4.orm.User;
import com.test4.test4.services.UserDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpSession;
import java.io.Serializable;


@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class UserController {




    @PostMapping("/tryLogin")
    public String TryLogin(HttpSession httpSession, @RequestBody RegisterBody body) {

        String password = body.password;
        String login = body.login;
        System.out.println("/tryLogin " + login.toString() + " " + password);

        User curUser=userDataService.GetUserByLogin(login);
        if ( curUser== null) {

            httpSession.setAttribute("isAuthorized", false);
            return "{ \"success\":" + false + "}";
        }

        //TODO password

        String secret = "secret";
        int iterations = 65536;
        int hashWidth = 128;
        Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, iterations, hashWidth);

        if( pbkdf2PasswordEncoder.matches(password,curUser.getPassword())){
            httpSession.setAttribute("isAuthorized", true);
            httpSession.setAttribute("login", login);
            return "{ \"success\":" + true + "}";

        }
        else {
            httpSession.setAttribute("isAuthorized", false);
            return "{ \"success\":" + false + "}";

        }

    }





    @PostMapping("/tryRegister")
    public String TryRegister(HttpSession httpSession, @RequestBody RegisterBody body) {
        String password = body.password;
        String login = body.login;
        System.out.println("/tryRegister " + login.toString() + " " + password);

        if (userDataService.GetUserByLogin(login) == null) {

            //TODO password


            User newUser = new User();
            newUser.setLogin(login);
            newUser.setPassword(getHash(password));


            httpSession.setAttribute("login", login);
            httpSession.setAttribute("isAuthorized", true);
            userDataService.PutUser(newUser);
            return "{ \"success\":" + true + "}";
        }


        System.out.println("{\"success\":" + false + "}");
        httpSession.setAttribute("isAuthorized", false);
        return "{ \"success\":" + false + "}";
    }

    public static int saltSize=16;


    public String getHash(String password){

        String secret = "secret";
        int iterations = 65536;
        int hashWidth = 128;
        Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, iterations, hashWidth);


        String encode = pbkdf2PasswordEncoder.encode(password);
        return encode;


    }

    @Autowired
    UserDataService userDataService;

    @GetMapping("/isAuthorized")
    public String isAuthorized(HttpSession session) {

        if((boolean)session.getAttribute("isAuthorized")){

            return "{ \"isAuthorized\":" + true + "}";
        }
        else  return "{ \"isAuthorized\":" + false + "}";



    }


    @GetMapping("/logOut")
    public String logOut(HttpSession session) {
        session.removeAttribute("isAuthorized");
        session.removeAttribute("login");
        return "{ \"success\":" + true + "}";



    }


}

class RegisterBody implements Serializable {
    String login;
    String password;

    public RegisterBody() {
    }

    public RegisterBody(String login, String password) {
        this.login = login;
        this.password = password;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}