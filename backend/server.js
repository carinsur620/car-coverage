
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import { readFileSync } from "node:fs";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

const allowedOrigins = (
  process.env.FRONTEND_ORIGINS ||
  "https://carinsur620.github.io"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  }
}));

app.use(express.json({ limit: "100kb" }));

// Load Firebase credentials from Render Secret Files.
const credentialsPath =
  process.env.FIREBASE_SERVICE_ACCOUNT_FILE ||
  "/etc/secrets/primeshield-firebase-admin.json";

const serviceAccount = JSON.parse(
  readFileSync(credentialsPath, "utf8")
);

if (serviceAccount.project_id !== "carinsurance-784eb") {
  throw new Error("Firebase service account belongs to the wrong project.");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const firebaseAuth = admin.auth();

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "PrimeShield Backend",
    status: "running"
  });
});

async function authenticateCustomer(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    req.customer = await firebaseAuth.verifyIdToken(
      authorization.slice(7)
    );

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

app.get("/api/me", authenticateCustomer, async (req, res) => {
  try {
    const snapshot = await db
      .collection("users")
      .doc(req.customer.uid)
      .get();

    if (!snapshot.exists) {
      return res.status(404).json({
        success: false,
        message: "Customer profile not found."
      });
    }

    const data = snapshot.data();

    if (data.blocked === true) {
      return res.status(403).json({
        success: false,
        message: "This account has been restricted."
      });
    }

    return res.json({
      success: true,
      profile: {
        email: data.email || req.customer.email || null,
        planCode: data.planCode || null,
        planName: data.planName || null,
        planPrice: data.planPrice ?? null,
        status: data.status || "pending",
        registrationCode: data.registrationCode || null,
        createdAt: data.createdAt || null
      }
    });
  } catch (error) {
    console.error("Profile error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve customer profile."
    });
  }
});

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`PrimeShield backend running on port ${PORT}`);
});
