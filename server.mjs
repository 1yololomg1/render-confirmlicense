   import express from "express";
     import admin from "firebase-admin";

     const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON || "{}");
     const sharedSecret = process.env.SHARED_SECRET;

     if (!sharedSecret) {
       console.error("SHARED_SECRET is missing.");
       process.exit(1);
     }

     admin.initializeApp({
       credential: admin.credential.cert(serviceAccount)
     });

     const app = express();
     app.use(express.json());

     app.post("/token", async (req, res) => {
       if (req.get("x-app-secret") !== sharedSecret) {
         return res.status(403).json({ error: "Forbidden" });
       }

       const uid = req.body?.uid || "desktop-user";
       try {
         const customToken = await admin.auth().createCustomToken(uid);
         res.json({ token: customToken, issued_at: new Date().toISOString() });
       } catch (err) {
         console.error(err);
         res.status(500).json({ error: "Token minting failed" });
       }
     });

     app.get("/", (req, res) => res.send("Token broker running."));
     const port = process.env.PORT || 3000;
     app.listen(port, () => console.log(`Listening on ${port}`));