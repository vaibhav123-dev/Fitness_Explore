import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
  path: "./env",
});

connectDB()
  .then(() => {
    app.listen(process.env.PORT, () => {
      console.log(`Running on port ${process.env.PORT}`);
    });
  })
  .catch((error) => {
    console.error("MongoDb connection failed", error);
  });
