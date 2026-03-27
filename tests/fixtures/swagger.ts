import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";

const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
SwaggerModule.setup("docs", app, document);
