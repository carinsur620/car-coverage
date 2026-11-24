
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";

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

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    }
  })
);

app.use(express.json({ limit: "100kb" }));

// Firebase Admin connection
if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Firebase service account is not configured.");
}

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const firebaseAuth = admin.auth();

// API health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "PrimeShield Backend",
    status: "running"
  });
});

// Verify customer authentication
async function authenticateCustomer(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    const token = authorization.slice(7);
    req.customer = await firebaseAuth.verifyIdToken(token);

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

// Retrieve the authenticated customer's profile
app.get("/api/me", authenticateCustomer, async (req, res) => {
  try {
    const uid = req.customer.uid;

    const snapshot = await db
      .collection("users")
      .doc(uid)
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
    console.error("Profile error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve customer profile."
    });
  }
});

// Unknown API routes
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

app.listen(PORT, () => {
  console.log(`PrimeShield backend running on port ${PORT}`);
});
