import { Body, Controller, Post } from "@nestjs/common";
import { exec } from "child_process";

@Controller("jobs")
export class JobController {
  @Post()
  run(@Body("cmd") cmd: string) {
    return exec(cmd);
  }
}
