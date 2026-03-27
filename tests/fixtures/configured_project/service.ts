import jwt from "jsonwebtoken";

const token = jwt.sign({ id: 1 }, "supersecret123");

export default token;
