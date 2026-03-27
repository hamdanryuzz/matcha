export function login(res: any, token: string) {
  res.cookie("token", token, { httpOnly: true, secure: false });
}
