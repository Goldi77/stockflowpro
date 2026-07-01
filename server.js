require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

function initFirebaseAdmin(){
  if(getApps().length) return;

  let serviceAccount;

  if(process.env.FIREBASE_SERVICE_ACCOUNT){
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  }else{
    serviceAccount = require("./serviceAccountKey.json");
  }

  initializeApp({ credential: cert(serviceAccount) });
}

initFirebaseAdmin();

const adminAuth = getAuth();
const adminDb = getFirestore();

async function getCaller(req){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if(!token) return null;

  const decoded = await adminAuth.verifyIdToken(token);
  const snap = await adminDb.collection("users").doc(decoded.uid).get();
  const profile = snap.exists ? snap.data() : {};

  return {
    uid: decoded.uid,
    email: decoded.email || "",
    profile
  };
}

async function requireAdmin(req, res, next){
  try{
    const caller = await getCaller(req);

    if(!caller){
      return res.status(401).json({ success:false, message:"Login required" });
    }

    if((caller.profile.role || "") !== "Admin"){
      return res.status(403).json({ success:false, message:"Only admin can perform this action" });
    }

    req.caller = caller;
    next();
  }catch(error){
    return res.status(401).json({ success:false, message:error.message });
  }
}

app.get("/", (req,res)=>{
  res.json({ success:true, message:"StockFlow Firebase Admin Backend Running" });
});

app.get("/health", (req,res)=>{
  res.json({ success:true, status:"ok" });
});

app.delete("/api/firebase/delete-user/:uid", requireAdmin, async (req,res)=>{
  try{
    const uid = req.params.uid;

    if(!uid){
      return res.status(400).json({ success:false, message:"UID required" });
    }

    if(uid === req.caller.uid){
      return res.status(400).json({ success:false, message:"Admin cannot delete own account from staff panel" });
    }

    try{
      await adminAuth.deleteUser(uid);
    }catch(error){
      // If user is already missing in Auth, still clean Firestore.
      if(error.code !== "auth/user-not-found") throw error;
    }

    await adminDb.collection("users").doc(uid).delete();

    res.json({ success:true, message:"User deleted from Firebase Auth and Firestore" });
  }catch(error){
    res.status(500).json({ success:false, message:error.message });
  }
});

app.post("/api/auth/reset-password", async (req,res)=>{
  try{
    const email = String(req.body.email || "").trim();
    const password = String(req.body.password || "");

    if(!email || !password){
      return res.status(400).json({ success:false, message:"Email and password required" });
    }

    const user = await adminAuth.getUserByEmail(email);
    await adminAuth.updateUser(user.uid, { password });

    res.json({ success:true, message:"Password updated successfully" });
  }catch(error){
    res.status(500).json({ success:false, message:error.message });
  }
});

app.use((req,res)=>{
  res.status(404).json({ success:false, message:"Route not found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>{
  console.log("StockFlow Firebase Admin backend running on port " + PORT);
});
