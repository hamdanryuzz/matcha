import { Controller, Get, Query } from "@nestjs/common";
import { HttpService } from "@nestjs/axios";

@Controller("proxy")
export class ProxyController {
  constructor(private readonly httpService: HttpService) {}

  @Get()
  proxy(@Query("url") url: string) {
    return this.httpService.get(url);
  }
}
