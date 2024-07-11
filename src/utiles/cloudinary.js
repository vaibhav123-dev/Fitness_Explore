import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

// Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET_KEY,
});

// upload files on cloudinary
const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;

    // upload the file on cloudinary
    const uploadResponse = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });

    // file has been uploaded successfully
    fs.unlinkSync(localFilePath); // remove locally saved temporary files as files uploaded on cloudinary
    return uploadResponse;
  } catch (error) {
    fs.unlinkSync(localFilePath); // remove locally saved temporary files as upload operation got failed
    return null;
  }
};

export { uploadOnCloudinary };
