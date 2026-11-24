
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

// Health check.
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "PrimeShield Backend",
    status: "running"
  });
});

// Verify Firebase customer authentication.
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

// Normalize registration codes.
function normalizeCode(value) {
  if (typeof value !== "string") return "";

  return value.trim().toUpperCase();
}

// Check whether a registration code exists, is unused,
// and has not expired.
async function checkRegistrationCode(code) {
  const codeRef = db.collection("registrationCodes").doc(code);
  const snapshot = await codeRef.get();

  if (!snapshot.exists) {
    return {
      valid: false,
      message: "Invalid registration code."
    };
  }

  const data = snapshot.data();

  if (data.status !== "unused") {
    return {
      valid: false,
      message: "This registration code has already been used or is unavailable."
    };
  }

  if (
    data.expiresAt &&
    typeof data.expiresAt.toMillis === "function" &&
    data.expiresAt.toMillis() <= Date.now()
  ) {
    return {
      valid: false,
      message: "This registration code has expired."
    };
  }

  if (!data.planCode || !data.planName || !data.planPrice) {
    return {
      valid: false,
      message: "This registration code is not configured correctly. Contact support."
    };
  }

  return {
    valid: true,
    planCode: data.planCode,
    planName: data.planName,
    planPrice: data.planPrice
  };
}

// Endpoint 1: Validate a registration code before account creation.
app.post("/api/registration/validate", async (req, res) => {
  try {
    const code = normalizeCode(req.body?.registrationCode);

    if (!code || code.length > 64) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid registration code."
      });
    }

    const result = await checkRegistrationCode(code);

    if (!result.valid) {
      return res.status(400).json({
        success: false,
        message: result.message
      });
    }

    return res.json({
      success: true,
      message: "Registration code verified.",
      plan: {
        planCode: result.planCode,
        planName: result.planName,
        planPrice: result.planPrice
      }
    });
  } catch (error) {
    console.error("Registration code validation error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to verify registration code."
    });
  }
});

// Endpoint 2: Create a customer profile and consume the code.
app.post("/api/register", authenticateCustomer, async (req, res) => {
  try {
    const code = normalizeCode(req.body?.registrationCode);
    const uid = req.customer.uid;
    const email = req.customer.email || null;

    if (!code || code.length > 64) {
      return res.status(400).json({
        success: false,
        message: "A valid registration code is required."
      });
    }

    const codeRef = db.collection("registrationCodes").doc(code);
    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (transaction) => {
      const codeSnapshot = await transaction.get(codeRef);
      const userSnapshot = await transaction.get(userRef);

      if (!codeSnapshot.exists) {
        return {
          success: false,
          status: 400,
          message: "Invalid registration code."
        };
      }

      if (userSnapshot.exists) {
        return {
          success: false,
          status: 409,
          message: "A customer profile already exists for this account."
        };
      }

      const codeData = codeSnapshot.data();

      if (codeData.status !== "unused") {
        return {
          success: false,
          status: 409,
          message: "This registration code has already been used or is unavailable."
        };
      }

      if (
        codeData.expiresAt &&
        typeof codeData.expiresAt.toMillis === "function" &&
        codeData.expiresAt.toMillis() <= Date.now()
      ) {
        return {
          success: false,
          status: 400,
          message: "This registration code has expired."
        };
      }

      if (
        !codeData.planCode ||
        !codeData.planName ||
        !codeData.planPrice
      ) {
        return {
          success: false,
          status: 400,
          message: "This registration code is not configured correctly."
        };
      }

      // Consume the code and create the profile atomically.
      transaction.update(codeRef, {
        status: "used",
        usedBy: uid,
        usedByEmail: email,
        usedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      transaction.set(userRef, {
        email,
        planCode: codeData.planCode,
        planName: codeData.planName,
        planPrice: codeData.planPrice,
        registrationCode: code,
        status: "waiting",
        blocked: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      return {
        success: true,
        planName: codeData.planName
      };
    });

    if (!result.success) {
      return res.status(result.status).json({
        success: false,
        message: result.message
      });
    }

    return res.status(201).json({
      success: true,
      message: "Customer account registered successfully.",
      planName: result.planName
    });
  } catch (error) {
    console.error("Customer registration error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to complete customer registration."
    });
  }
});

// Get authenticated customer's profile.
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

// API fallback.
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`PrimeShield backend running on port ${PORT}`);
});
