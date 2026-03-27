import session from "express-session";

export function bootstrap(app: any) {
  app.use(
    session({
      secret: "keyboard-cat",
      resave: false,
      saveUninitialized: false,
    }),
  );
}
