const dangerous = /(a+)+$/;

export function validate(input: string) {
  return dangerous.test(input);
}
