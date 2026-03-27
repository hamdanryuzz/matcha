import { Controller, Post } from "@nestjs/common";

@Controller("users")
export class UsersController {
  @Post()
  create() {
    return { ok: true };
  }
}

export function bootstrap(app: any) {
  app.enableCors({ origin: "*" });
}
