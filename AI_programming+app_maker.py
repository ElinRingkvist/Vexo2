// server.js
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET; // Use env variable in production

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// --- Schemas ---

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
});

const VersionSchema = new mongoose.Schema({
  code: String,
  createdAt: { type: Date, default: Date.now },
});

const ProjectSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  description: String,
  code: { type: String, required: true },
  versions: [VersionSchema],
  assets: [String], // file URLs
  inputData: {
    text: String,
    speechTranscript: String,
    drawingData: mongoose.Schema.Types.Mixed, // e.g. JSON for drawing strokes
  },
  isPublic: { type: Boolean, default: false },
  deployedUrl: String, // URL after deployment
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Project = mongoose.model("Project", ProjectSchema);

// --- Middleware ---
app.use(cors());
app.use(express.json());

// Serve uploads folder statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- Auth Middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Missing token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// --- Routes ---

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    if (await User.findOne({ username })) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, passwordHash });
    await newUser.save();

    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user)
      return res.status(400).json({ message: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid username or password" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "12h" }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Create Project with input data
app.post("/api/projects", authenticateToken, async (req, res) => {
  try {
    const { title, description, code, inputData, isPublic } = req.body;
    if (!title || !code)
      return res.status(400).json({ message: "Title and code required" });

    const project = new Project({
      ownerId: req.user.id,
      title,
      description,
      code,
      versions: [{ code }],
      inputData: inputData || {},
      isPublic: !!isPublic,
      assets: [],
    });

    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get user projects
app.get("/api/projects", authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find({ ownerId: req.user.id }).sort({
      updatedAt: -1,
    });
    res.json(projects);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get public project by ID
app.get("/api/projects/public/:id", async (req, res) => {
  try {
    const project = await Project.findOne({
      _id: req.params.id,
      isPublic: true,
    });
    if (!project)
      return res.status(404).json({ message: "Project not found or not public" });

    res.json(project);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update project + versioning
app.put("/api/projects/:id", authenticateToken, async (req, res) => {
  try {
    const { title, description, code, inputData, isPublic } = req.body;
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: "Project not found" });
    if (project.ownerId.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    if (title) project.title = title;
    if (description) project.description = description;
    if (code && code !== project.code) {
      project.code = code;
      project.versions.push({ code });
    }
    if (inputData) project.inputData = inputData;
    if (typeof isPublic === "boolean") project.isPublic = isPublic;

    project.updatedAt = new Date();

    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Upload asset (image/drawing)
app.post(
  "/api/upload",
  authenticateToken,
  upload.single("file"),
  (req, res) => {
    if (!req.file)
      return res.status(400).json({ message: "No file uploaded" });

    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ url: fileUrl });
  }
);

// Add asset URL to project
app.post("/api/projects/:id/assets", authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "Missing asset URL" });

    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: "Project not found" });
    if (project.ownerId.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    project.assets.push(url);
    project.updatedAt = new Date();
    await project.save();

    res.json(project);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Deploy project (simulate deployment, assign public URL)
app.post("/api/projects/:id/deploy", authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: "Project not found" });
    if (project.ownerId.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    // Simulate deployment by assigning a public URL path
    project.deployedUrl = `/deployed/${project._id}`;
    project.isPublic = true; // deployment implies public access
    project.updatedAt = new Date();
    await project.save();

    res.json({ deployedUrl: project.deployedUrl });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Serve deployed projects publicly by rendering stored code (simplified)
app.get("/deployed/:projectId", async (req, res) => {
  try {
    const project = await Project.findById(req.params.projectId);
    if (!project || !project.isPublic || !project.deployedUrl)
      return res.status(404).send("Project not found or not deployed");

    // For security: sanitize or restrict code before serving in production!
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>${project.title}</title></head>
      <body>
      ${project.code}
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
