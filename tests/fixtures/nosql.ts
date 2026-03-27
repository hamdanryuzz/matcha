import { Controller, Get, Query } from "@nestjs/common";

@Controller("users")
export class UserController {
  constructor(private readonly model: any) {}

  @Get()
  search(@Query() filter: any) {
    return this.model.find(filter);
  }
}
