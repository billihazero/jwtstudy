package com.example.jwtproject.controller;

import com.example.jwtproject.dto.JoinDTO;
import com.example.jwtproject.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO){

        joinService.joinProcess(joinDTO);

        return "ok";
    }

}
