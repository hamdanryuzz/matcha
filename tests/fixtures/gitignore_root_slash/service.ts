import jwt from "jsonwebtoken";

const token = jwt.sign({ id: 123 }, "supersecret123");

export default token;
