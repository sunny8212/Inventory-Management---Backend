  const express = require("express");
  const mongoose = require("mongoose");
  const bcrypt = require("bcrypt");
  const jwt = require("jsonwebtoken");
  const app = express();
  const port = 8000; 
  const cors = require('cors');
  const fs = require("fs");
  const path = require("path");
  const { Parser } = require("json2csv");


  // Middleware to parse JSON request bodies
  app.use(express.json());
  app.use(cors());


  // Connect to MongoDB
  mongoose
    .connect("mongodb+srv://padariyasunny:NJUdakluqHXMtejz@yt.1qrya.mongodb.net/Inventory", {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("Error connecting to MongoDB:", err));

    JWT_SECRET = 'abcdefghijklmnopqrstuvwxyz1234567890';

  // Define a schema for users
  const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["Admin", "Manager", "Viewer"], // Ensure role is a string from these options
      required: true,
      default: "Viewer", // Default role if not provided
    },
  });
  
  const User = mongoose.model("User", userSchema);

  // Create a new user (POST)
  app.post("/api/users", async (req, res) => {
    try {
      const { name, email } = req.body;

      if (!name || !email) {
        return res.status(400).json({ message: "Name and email are required." });
      }

      const newUser = new User({ name, email });
      await newUser.save(); // Save to MongoDB
      res.status(201).json(newUser);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error creating user", error });
    }
  });

  // Read all users (GET)
  app.get("/api/users", async (req, res) => {
    try {
      const users = await User.find(); // Fetch all users from MongoDB
      res.json(users);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error fetching users", error });
    }
  });

  // Read a single user by ID (GET)
  app.get("/api/users/:id", async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(user);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error fetching user", error });
    }
  });

  // Update a user by ID (PUT)
  app.put("/api/users/:id", async (req, res) => {
    try {
      const { name, email } = req.body;

      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        { name, email },
        { new: true, runValidators: true }
      );

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json(updatedUser);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error updating user", error });
    }
  });

  // Delete a user by ID (DELETE)
  app.delete("/api/users/:id", async (req, res) => {
    try {
      const deletedUser = await User.findByIdAndDelete(req.params.id);

      if (!deletedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ message: "User deleted" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error deleting user", error });
    }
  });

  //REGISTER

  app.post("/api/auth/register", async (req, res) => {
    try {
      const { name, email, password, role } = req.body;
  
      if (!name || !email || !password || !role) {
        return res.status(400).json({ message: "Name, email, password, and role are required." });
      }
  
      // Check if the email already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists." });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new user with the role
      const newUser = new User({
        name,
        email,
        password: hashedPassword,
        role, // Assign the role provided by the user
      });
  
      await newUser.save(); // Save to MongoDB
  
      // Generate JWT token
      const token = jwt.sign(
        { id: newUser._id, email: newUser.email, role: newUser.role },
        JWT_SECRET,
        { expiresIn: "1h" } // Token expires in 1 hour
      );
  
      // Return response with the user and token
      return res.status(201).json({
        message: "User registered successfully.",
        token,
        user: { id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role },
      });
    } catch (error) {
      console.error("Error during registration:", error);
      return res.status(500).json({ message: "Error registering user", error });
    }
  });
  
  
  

  // Middleware for Role-Based Access
  const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized access" });
    }

    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded; // Attach user information to the request
      next();
    } catch (error) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };

  const authorize = (roles) => {
    return (req, res, next) => {
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: "Forbidden: Access denied" });
      }
      next();
    };
  };  


  // User Login (POST)
  app.post("/api/auth/login", async (req, res) => {
    try {
      const { email, password } = req.body;
  
      if (!email || !password) {
        return res
          .status(400)
          .json({ message: "Email and password are required." });
      }
  debugger
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }
  
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password." });
      }
  
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: "1h" }
      );
  
      res.json({
        message: "Login successful",
        token,
        user: { id: user._id, name: user.name, email: user.email, role: user.role },
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Error logging in", error });
    }
  });
  

  // Protected Route (Example)
  app.get("/api/protected", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized access" });
      }

      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, JWT_SECRET);

      res.json({ message: "Protected content accessed", user: decoded });
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: "Invalid or expired token" });
    }
  });

  // Example: Admin-only route
  app.get("/api/admin", authenticate, authorize(["Admin"]), (req, res) => {
    res.json({ message: "Admin content accessed" });
  });

  // Example: Admin and Manager route
  app.get("/api/manager", authenticate, authorize(["Admin", "Manager"]), (req, res) => {
    res.json({ message: "Manager content accessed" });
  });


  // User Logout (POST)
  app.post("/api/auth/logout", (req, res) => {
    // JWT-based logout is typically handled on the client by clearing the token
    res.json({ message: "Logout successful" });
  });

  // Start the server
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });

// Connect to MongoDB
mongoose.connect("mongodb+srv://padariyasunny:NJUdakluqHXMtejz@yt.1qrya.mongodb.net/Inventory", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  sku: { type: String, required: true, unique: true },
  category: { type: String, required: true },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true },
  supplier: { type: String, required: true },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
  restocked: { type: Number, default: 0 }, // Track restocks
  sold: { type: Number, default: 0 }, // Track sales
  },
  { timestamps: true } 
);
const Product = mongoose.model("Product", productSchema);


// Add Product API
app.post("/api/products", async (req, res) => {
  try {
    const { name, sku, category, quantity, price, supplier, status } = req.body;

    // Ensure all fields are present
    if (!name || !sku || !category || !quantity || !price || !supplier) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const newProduct = new Product({ name, sku, category, quantity, price, supplier, status });
    await newProduct.save();
    res.status(201).json({ message: "Product added successfully", product: newProduct });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});

// Get All Products
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Error fetching products", error: error.message });
  }
});


// Get Products based on id
  app.get("/api/products/:id", async (req, res) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      console.error("Error fetching product:", error);
      res.status(500).json({ message: "Error fetching product", error: error.message });
    }
  });


app.delete("/api/products/:id", async (req, res) => {
  try {
    console.log("Received delete request for ID:", req.params.id); // ✅ Log received ID

    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    
    if (!deletedProduct) {
      return res.status(404).json({ message: "Product not found" });
    }
    
    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ message: "Error deleting product", error: error.message });
  }
});





// Edit the product details - Adjust quantity dynamically
app.put("/api/product/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, sku, category, price, supplier, status, restocked, sold } = req.body;

    // Find the existing product
    const existingProduct = await Product.findById(id);
    if (!existingProduct) {
      return res.status(404).json({ message: "Product not found" });
    }

    // Ensure restocked and sold values are numbers
    const restockedAmount = Number(restocked) || 0;
    const soldAmount = Number(sold) || 0;

    // Calculate new quantity
    let newQuantity = existingProduct.quantity + restockedAmount - soldAmount;
    if (newQuantity < 0) {
      return res.status(400).json({ message: "Error: Quantity cannot be negative!" });
    }

    // Update the fields while adjusting quantity
    existingProduct.name = name;
    existingProduct.sku = sku;
    existingProduct.category = category;
    existingProduct.quantity = newQuantity;
    existingProduct.price = price;
    existingProduct.supplier = supplier;
    existingProduct.status = status;
    existingProduct.restocked += restockedAmount;
    existingProduct.sold += soldAmount;

    // Save updated product
    const updatedProduct = await existingProduct.save();

    res.json({ message: "Product updated successfully", product: updatedProduct });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ message: "Error updating product", error: error.message });
  }
});

// Get stock levels by category
app.get("/api/stock-by-category", async (req, res) => {
  try {
    const stockLevels = await Product.aggregate([
      {
        $group: {
          _id: "$category",
          totalStock: { $sum: "$quantity" },
        },
      },
      {
        $sort: { totalStock: -1 },
      },
    ]);

    res.json(stockLevels);
  } catch (error) {
    console.error("Error fetching stock by category:", error);
    res.status(500).json({ message: "Error fetching stock levels" });
  }
});

//  Get Product-Wise Monthly Stock Updates
app.get("/api/product-monthly-stock-updates", async (req, res) => {
  try {
    const stockUpdates = await Product.aggregate([
      {
        $unwind: "$updatedAt", // Ensure updates are tracked
      },
      {
        $group: {
          _id: {
            product: "$name",
            month: { $month: "$updatedAt" }, // Extract month
            year: { $year: "$updatedAt" }, // Extract year
          },
          restocked: { $sum: "$restocked" }, // Sum of restocked
          sold: { $sum: "$sold" }, // Sum of sold
        },
      },
      { $sort: { "_id.year": 1, "_id.month": 1 } },
    ]);

    const formattedStockUpdates = stockUpdates.map((entry) => ({
      product: entry._id.product,
      month: new Date(0, entry._id.month - 1).toLocaleString("en", {
        month: "long",
      }),
      restocked: entry.restocked || 0,
      sold: entry.sold || 0,
    }));

    res.status(200).json(formattedStockUpdates);
  } catch (error) {
    console.error("Error fetching product-wise monthly stock updates:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Export Product-Wise Monthly Stock Updates as CSV
app.get("/api/export-product-monthly-stock", async (req, res) => {
  try {
    const stockUpdates = await Product.aggregate([
      {
        $group: {
          _id: {
            product: "$name",
            month: { $month: "$updatedAt" },
            year: { $year: "$updatedAt" },
          },
          restocked: { $sum: "$restocked" },
          sold: { $sum: "$sold" },
        },
      },
      { $sort: { "_id.year": 1, "_id.month": 1 } },
    ]);

    const formattedStockUpdates = stockUpdates.map((entry) => ({
      product: entry._id.product,
      month: new Date(0, entry._id.month - 1).toLocaleString("en", {
        month: "long",
      }),
      year: entry._id.year,
      restocked: entry.restocked || 0,
      sold: entry.sold || 0,
    }));

    // Convert JSON data to CSV format
    const json2csvParser = new Parser({ fields: ["product", "month", "year", "restocked", "sold"] });
    const csvData = json2csvParser.parse(formattedStockUpdates);

    // Send CSV file as response
    res.setHeader("Content-Disposition", "attachment; filename=product_monthly_stock.csv");
    res.set("Content-Type", "text/csv");
    res.status(200).send(csvData);
  } catch (error) {
    console.error("Error exporting product stock CSV:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});