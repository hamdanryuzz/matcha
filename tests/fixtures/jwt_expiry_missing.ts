import { JwtModule } from "@nestjs/jwt";

export const authConfig = JwtModule.register({
  secret: process.env.JWT_SECRET_KEY,
});
