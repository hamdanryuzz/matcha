import { NestFactory } from "@nestjs/core";

async function bootstrap() {
  const app = await NestFactory.create({});
  const isDev = process.env.NODE_ENV !== "production";

  if (isDev) {
    app.enableCors({
      origin: "*",
    });
  }
}
