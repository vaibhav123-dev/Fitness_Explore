import { Router } from "express";
import {
  getCurrentUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  updatePassword,
  updateUserAvatar,
  updateUserProfileDetails,
} from "../controllers/user.controller.js";
import { upload } from "./../middlewares/multer.middleware.js";
import { verifyJWT } from "./../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(upload.single("avatar"), registerUser);

router.route("/login").post(loginUser);

//secured routes
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/password-update").post(verifyJWT, updatePassword);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/update-profile-details").patch(verifyJWT, updateUserProfileDetails);
router.route("/update-avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar);

export default router;
