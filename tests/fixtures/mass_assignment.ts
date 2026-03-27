import { Body, Controller, Post } from "@nestjs/common";

@Controller("users")
export class UserController {
  constructor(private readonly repo: any) {}

  @Post()
  create(@Body() body: any) {
    return this.repo.save(body);
  }
}
