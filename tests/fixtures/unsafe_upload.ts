import { Controller, Post, UseInterceptors } from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { diskStorage } from "multer";

@Controller("upload")
export class UploadController {
  @Post()
  @UseInterceptors(
    FileInterceptor("file", {
      storage: diskStorage({
        filename: (req, file, cb) => cb(null, file.originalname),
      }),
    }),
  )
  upload() {
    return { ok: true };
  }
}
