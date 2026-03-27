import { Controller, Get, Query, Res } from "@nestjs/common";

@Controller("auth")
export class AuthController {
  @Get("redirect")
  go(@Query("next") next: string, @Res() res: any) {
    return res.redirect(next);
  }
}
