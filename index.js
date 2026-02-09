require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 8000;

const serviceAccount = require("./firebase-adminsdk.json");

app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.19bqwkr.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const simplifyMongoDBId = (id) => {
  if (id == null) return null;

  if (typeof id === "string") return id;

  if (typeof id === "object" && "_id" in id) {
    return simplifyMongoDBId(id._id);
  }

  if (typeof id === "object" && typeof id.toString === "function") {
    return id.toString();
  }

  return null;
};

async function run() {
  try {
    await client.connect();
    console.log("Database connection successful");
    const db = client.db("local_chef_bazaar_db");

    const usersCollection = db.collection("users");
    const mealsCollection = db.collection("meals");
    const ordersCollection = db.collection("orders");
    const reviewsCollection = db.collection("reviews");
    const favoritesCollection = db.collection("favorites");
    const requestsCollection = db.collection("requests");
    const paymentsCollection = db.collection("payments");

    // =======================
    // JWT VERIFICATION MIDDLEWARE
    // =======================
    const auth = (...roles) => {
      return async (req, res, next) => {
        try {
          const bearerToken = req.headers.authorization;
          if (!bearerToken) {
            return res.status(401).send({ message: "Unauthorized" });
          }

          const token = bearerToken.split(" ")[1];
          const decoded = await admin.auth().verifyIdToken(token);
          const user = await usersCollection.findOne({ email: decoded.email });
          if (!user) {
            return res.status(401).send({ message: "Unauthorized" });
          }
          if (!roles.includes(user.role)) {
            return res.status(403).send({ message: "Forbidden" });
          }
          user._id = simplifyMongoDBId(user._id);
          req.user = user;
          next();
        } catch (error) {
          return res.status(401).send({ message: "Unauthorized" });
        }
      };
    };

    // =======================
    // AUTH API (Login)
    // =======================
    // Login with email and password - returns Firebase access token
    app.post("/api/v1/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        // Validate required fields
        if (!email || !password) {
          return res.status(400).send({
            message: "Email and password are required",
          });
        }

        // Firebase Auth REST API for sign-in with email/password
        const firebaseApiKey = process.env.FIREBASE_API_KEY;
        if (!firebaseApiKey) {
          return res.status(500).send({
            message: "Firebase API key not configured",
          });
        }

        const firebaseAuthUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseApiKey}`;

        const response = await fetch(firebaseAuthUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            password,
            returnSecureToken: true,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          const errorMessage = data.error?.message || "Authentication failed";
          return res.status(401).send({
            message: errorMessage,
          });
        }

        const user = await usersCollection.findOne({ email });

        res.send({
          message: "Login successful",
          accessToken: data.idToken,
          refreshToken: data.refreshToken,
          expiresIn: data.expiresIn,
          user: user
            ? {
                _id: simplifyMongoDBId(user._id),
                email: user.email,
                name: user.name || user.displayName,
                role: user.role,
                status: user.status,
              }
            : null,
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).send({
          message: "Login failed",
          error: error.message,
        });
      }
    });

    // =======================
    // 1. USERS API COLLECTION

    // =======================
    // Get all users (Admin only)
    app.get("/api/v1/users", auth("admin"), async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send({ users });
    });

    // Get current user by email (for fetching user data after login)
    app.get(
      "/api/v1/users/email/:email",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const email = req.params.email;

        //  users can only get their own data
        if (req.user.role !== "admin" && req.user.email !== email) {
          return res
            .status(403)
            .send({ message: "You can only view your own profile" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        const { password, ...userWithoutPassword } = user;
        res.send({ user: userWithoutPassword });
      },
    );

    // Create new user
    app.post("/api/v1/users", async (req, res) => {
      const userData = req.body;

      // Check if user already exists
      const existingUser = await usersCollection.findOne({
        email: userData.email,
      });

      if (existingUser) {
        return res.send({ message: "User already exists", insertedId: null });
      }
      //default value add for users and admin
      // Set default values
      const newUser = {
        ...userData,
        role: "user",
        status: "active",
        createdAt: new Date().toISOString(),
      };

      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    // Update user by ID (only admin can update)
    app.patch("/api/v1/users/:id", auth("admin"), async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;

      if (req.user.role !== "admin") {
        return res.status(403).send({ message: "Only admin can update user" });
      }

      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateData },
      );

      res.send(result);
    });

    // Mark user as fraud (Admin only)
    app.patch("/api/v1/users/:id/fraud", auth("admin"), async (req, res) => {
      const id = req.params.id;

      // Find the user
      const user = await usersCollection.findOne({ _id: new ObjectId(id) });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      // Cannot mark admin as fraud
      if (user.role === "admin") {
        return res
          .status(403)
          .send({ message: "Cannot mark an admin as fraud" });
      }

      // Check if already fraud
      if (user.status === "fraud") {
        return res
          .status(400)
          .send({ message: "User is already marked as fraud" });
      }

      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: "fraud" } },
      );

      res.send({ message: "User has been marked as fraud", result });
    });

    // =======================
    // 2. MEALS API
    // =======================
    // Get all meals with pagination, sorting, and search
    app.get("/api/v1/meals", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const sort = req.query.sort;
      const order = req.query.order === "desc" ? -1 : 1;
      const search = req.query.search;

      let query = {};
      if (search) {
        query = {
          $or: [
            { foodName: { $regex: search, $options: "i " } },
            { chefName: { $regex: search, $options: "i " } },
          ],
        };
      }

      let sortOption = {};
      if (sort) {
        sortOption[sort] = order;
      }

      const skip = (page - 1) * limit;
      const total = await mealsCollection.countDocuments(query);
      const meals = await mealsCollection
        .find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .toArray();

      for (const meal of meals) {
        const reviews = await reviewsCollection
          .find({ foodId: meal._id.toString() })
          .toArray();
        const averageRating =
          reviews.reduce((sum, review) => sum + review.rating, 0) /
          reviews.length;
        const totalReviews = reviews.length;
        meal.rating = Number(averageRating?.toFixed(1)) || 0;
        meal.totalReviews = totalReviews;
      }

      res.send({
        meals,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
    });

    // Get meals by chef (chefs can only see their own meals, admin can see all)
    app.get("/api/v1/meals/chef", auth("chef", "admin"), async (req, res) => {
      const meals = await mealsCollection
        .find({ chefId: req.user.chefId })
        .toArray();

      for (const meal of meals) {
        const reviews = await reviewsCollection
          .find({ foodId: meal._id })
          .toArray();
        const averageRating =
          reviews.reduce((sum, review) => sum + review.rating, 0) /
          reviews.length;
        const totalReviews = reviews.length;
        meal.rating = Number(averageRating?.toFixed(1)) || 0;
        meal.totalReviews = totalReviews;
      }

      res.send({ meals });
    });
    // Get meal by ID
    app.get(
      "/api/v1/meals/:id",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const id = req.params.id;
        const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });

        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        const isFavorite = (await favoritesCollection.findOne({
          userEmail: req.user.email,
          mealId: id,
        }))
          ? true
          : false;

        const reviews = await reviewsCollection.find({ foodId: id }).toArray();
        const averageRating =
          reviews.length > 0
            ? reviews.reduce((sum, review) => sum + review.rating, 0) /
              reviews.length
            : 0;
        const totalReviews = reviews.length;
        const canReview = reviews.some(
          (review) => review.reviewerEmail === req.user.email,
        );

        meal.isFavorite = isFavorite;
        meal.isReviewed = canReview;
        meal.rating = Number(averageRating?.toFixed(1)) || 0;
        meal.totalReviews = totalReviews;

        res.send(meal);
      },
    );
    //  meal is automatically linked to the chef
    // Create new meal (Chef only )
    app.post("/api/v1/meals", auth("chef"), async (req, res) => {
      const mealData = req.body;

      // Check if chef is fraud - fraud chefs cannot create meals
      if (req.user.status === "fraud") {
        return res.status(403).send({
          message: "Your account is marked as fraud. You cannot create meals.",
        });
      }

      // Check if chef has a chefId assigned
      if (req.user.role !== "chef") {
        return res.status(403).send({
          message: "Only chefs can create meals.",
        });
      }

      // Force chefId to be the authenticated chef's chefId (generated by admin)
      const newMeal = {
        foodName: mealData?.foodName,
        chefName: req.user.name,
        foodImage: mealData?.foodImage,
        price: mealData?.price,
        rating: 0,
        ingredients: mealData?.ingredients || [],
        deliveryArea: mealData?.deliveryArea,
        estimatedDeliveryTime: mealData?.estimatedDeliveryTime,
        chefExperience: mealData?.chefExperience,
        chefId: req.user.chefId,
        userEmail: req.user.email,
        createdAt: new Date().toISOString(),
      };

      const result = await mealsCollection.insertOne(newMeal);
      res.send(result);
    });

    // Update meal (chefs can only update their own meals, admin can update any)
    app.patch("/api/v1/meals/:id", auth("chef", "admin"), async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;

      // Find the meal first to check ownership
      const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
      if (!meal) {
        return res.status(404).send({ message: "Meal not found" });
      }

      // Check ownership: chef can only update their own meals (using chefId field)
      if (req.user.role !== "admin" && meal?.chefId !== req.user?.chefId) {
        return res
          .status(403)
          .send({ message: "You can only update your own meals" });
      }

      // Prevent changing chefId
      delete updateData.chefId;
      delete updateData.chefEmail;

      const result = await mealsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateData },
      );

      res.send(result);
    });

    // Delete meal (chefs can only delete their own meals, admin can delete any)
    app.delete("/api/v1/meals/:id", auth("chef", "admin"), async (req, res) => {
      const id = req.params.id;

      // Find the meal first to check ownership
      const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
      if (!meal) {
        return res.status(404).send({ message: "Meal not found" });
      }

      // Check ownership: chef can only delete their own meals (using chefId field)
      if (req.user.role !== "admin" && meal?.chefId !== req.user?.chefId) {
        return res
          .status(403)
          .send({ message: "You can only delete your own meals" });
      }

      // Start a session for transaction
      const session = client.startSession();

      try {
        session.startTransaction();

        // Delete related data within the transaction
        await reviewsCollection.deleteMany(
          { foodId: new ObjectId(id) },
          { session },
        );
        await favoritesCollection.deleteMany(
          { mealId: new ObjectId(id) },
          { session },
        );
        await ordersCollection.deleteMany(
          { foodId: new ObjectId(id) },
          { session },
        );
        await paymentsCollection.deleteMany(
          { mealId: new ObjectId(id) },
          { session },
        );

        // Delete the meal itself
        const result = await mealsCollection.deleteOne(
          { _id: new ObjectId(id) },
          { session },
        );

        // Commit the transaction
        await session.commitTransaction();

        res.send(result);
      } catch (error) {
        // Rollback the transaction on error
        await session.abortTransaction();
        console.error("Transaction aborted due to error:", error);
        res
          .status(500)
          .send({ message: "Failed to delete meal", error: error.message });
      } finally {
        // End the session
        await session.endSession();
      }
    });

    // =======================
    // 3. ORDERS API
    // =======================
    // Get all orders (admin can see all orders)
    app.get("/api/v1/orders", auth("admin"), async (req, res) => {
      const page = parseInt(req.query?.page) || 1;
      const limit = parseInt(req.query?.limit) || 10;
      const sort = req.query?.sort;
      const order = req.query?.order === "desc" ? -1 : 1;
      const paymentStatus = req.query?.paymentStatus;
      const orderStatus = req.query?.orderStatus;
      const search = req.query?.search;

      let query = {};
      if (search) {
        query = {
          $or: [
            { mealName: { $regex: search, $options: "i" } },
            { userEmail: { $regex: search, $options: "i" } },
            { userName: { $regex: search, $options: "i" } },
          ],
        };
      }

      if (paymentStatus) {
        query.paymentStatus = paymentStatus;
      }

      if (orderStatus) {
        query.orderStatus = orderStatus;
      }

      let sortOption = {};
      if (sort) {
        sortOption[sort] = order;
      }

      const skip = (page - 1) * limit;
      const total = await ordersCollection.countDocuments(query);
      const orders = await ordersCollection
        .find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .toArray();
      res.send({ orders, total, page, totalPages: Math.ceil(total / limit) });
    });

    // Get orders by user (users can only see their own orders)
    app.get(
      "/api/v1/orders/user",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const orders = await ordersCollection
          .find({ userEmail: req.user?.email })
          .sort({ orderTime: -1 })
          .toArray();
        res.send({ orders });
      },
    );

    // Get orders by chef (chefs can only see orders for their meals)
    app.get("/api/v1/orders/chef", auth("chef"), async (req, res) => {
      const page = parseInt(req.query?.page) || 1;
      const limit = parseInt(req.query?.limit) || 10;
      const sort = req.query?.sort;
      const order = req.query?.order === "desc" ? -1 : 1;
      const search = req.query?.search;
      const paymentStatus = req.query?.paymentStatus;
      const orderStatus = req.query?.orderStatus;

      let query = {};
      if (search) {
        query = {
          $or: [
            { mealName: { $regex: search, $options: "i" } },
            { userEmail: { $regex: search, $options: "i" } },
            { userName: { $regex: search, $options: "i" } },
          ],
        };
      }

      if (paymentStatus) {
        query.paymentStatus = paymentStatus;
      }

      if (orderStatus) {
        query.orderStatus = orderStatus;
      }

      let sortOption = {};
      if (sort) {
        sortOption[sort] = order;
      }

      query.chefId = req.user?.chefId;

      const skip = (page - 1) * limit;
      const total = await ordersCollection.countDocuments(query);
      const orders = await ordersCollection
        .find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .toArray();
      res.send({ orders, total, page, totalPages: Math.ceil(total / limit) });
    });

    // Create new order (order is automatically linked to the authenticated user)
    app.post(
      "/api/v1/orders",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const orderData = req.body;

        // Check if user is fraud - fraud users cannot place orders
        if (req.user.status === "fraud") {
          return res.status(403).send({
            message:
              "Your account is marked as fraud. You cannot place orders.",
          });
        }

        // Validate required fields
        if (
          !orderData.foodId ||
          !orderData.quantity ||
          !orderData.userAddress
        ) {
          return res.status(400).send({
            message: "Missing required fields: foodId, quantity, userAddress",
          });
        }

        // Get meal details to fill order data
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(orderData.foodId),
        });
        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        // Create order with auto-filled data from meal and user
        const newOrder = {
          foodId: orderData.foodId,
          mealName: meal.foodName,
          price: meal.price,
          quantity: parseInt(orderData.quantity),
          chefId: meal.chefId,
          chefName: meal.chefName,
          userEmail: req.user.email,
          userName: req.user.name,
          userAddress: orderData.userAddress,
          orderStatus: "pending",
          paymentStatus: "pending",
          orderTime: new Date().toISOString(),
        };

        const result = await ordersCollection.insertOne(newOrder);
        res.send(result);
      },
    );

    // Update order status (only chef who owns the meal or admin can update)
    app.patch("/api/v1/orders/:id", auth("chef", "admin"), async (req, res) => {
      const id = req.params.id;
      const { orderStatus } = req?.body;

      // Find the order first to check ownership
      const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
      if (!order) {
        return res.status(404).send({ message: "Order not found" });
      }

      // Check ownership: chef can only update orders for their meals (using chefId field)
      if (req?.user?.role !== "admin" && order?.chefId !== req?.user?.chefId) {
        return res
          .status(403)
          .send({ message: "Only chefs can update their own orders" });
      }

      // Validate order status transitions
      const currentStatus = order?.orderStatus;
      const validTransitions = {
        pending: ["cancelled", "accepted"],
        accepted: ["delivered"],
        cancelled: [],
        delivered: [],
      };

      if (
        orderStatus &&
        !validTransitions[currentStatus]?.includes(orderStatus)
      ) {
        return res.status(400).send({
          message: `Invalid status transition from '${currentStatus}' to '${orderStatus}'`,
        });
      }

      if (orderStatus === "delivered" && order.paymentStatus !== "paid") {
        return res.status(400).send({
          message: "Order must be paid before being delivered",
        });
      }

      const result = await ordersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { orderStatus } },
      );

      res.send(result);
    });

    // =======================
    // 4. REVIEWS API
    // =======================
    // Get all reviews (for home page)
    app.get("/api/v1/reviews", async (req, res) => {
      const limit = parseInt(req.query.limit) || 10;
      const reviews = await reviewsCollection
        .find({
          rating: { $gte: 4 },
        })
        .sort({ date: -1 })
        .limit(limit)
        .toArray();
      res.send({ reviews });
    });

    // Get reviews by food ID
    app.get("/api/v1/reviews/meal/:foodId", async (req, res) => {
      const foodId = req.params.foodId;
      const reviews = await reviewsCollection
        .find({ foodId })
        .sort({ date: -1 })
        .toArray();
      res.send({ reviews });
    });

    // Get reviews by user email (users can only see their own reviews)
    app.get(
      "/api/v1/reviews/user",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const reviews = await reviewsCollection
          .find({ reviewerEmail: req.user.email })
          .sort({ date: -1 })
          .toArray();
        res.send({ reviews });
      },
    );

    // Create review (review is automatically linked to the authenticated user)
    app.post(
      "/api/v1/reviews",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const reviewData = req.body;

        // Validate required fields
        if (!reviewData.foodId || !reviewData.rating || !reviewData.comment) {
          return res.status(400).send({
            message: "Missing required fields: foodId, rating, comment",
          });
        }

        // Get meal details to include meal name
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(reviewData.foodId),
        });
        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        const isMyMeal = meal.chefId === req.user.chefId;

        if (isMyMeal) {
          return res
            .status(400)
            .send({ message: "You cannot review your own meal" });
        }

        const existingReview = await reviewsCollection.findOne({
          foodId: reviewData.foodId,
          reviewerEmail: req.user.email,
        });
        if (existingReview) {
          return res
            .status(400)
            .send({ message: "You have already reviewed this meal" });
        }

        // Force reviewer info to be the authenticated user
        const newReview = {
          foodId: reviewData.foodId,
          mealName: meal.foodName,
          rating: parseInt(reviewData.rating),
          comment: reviewData.comment,
          reviewerEmail: req.user.email,
          reviewerName: req.user.name || req.user.displayName,
          reviewerImage: req.user.photoURL || req.user.photo || req.user.image,
          date: new Date().toISOString(),
        };

        const result = await reviewsCollection.insertOne(newReview);
        res.send(result);
      },
    );

    // Update review (users can only update their own reviews)
    app.patch(
      "/api/v1/reviews/:id",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const id = req.params.id;
        const updateData = req.body;

        // Find the review first to check ownership
        const review = await reviewsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Check ownership: users can only update their own reviews
        if (
          req.user.role !== "admin" &&
          review.reviewerEmail !== req.user.email
        ) {
          return res
            .status(403)
            .send({ message: "You can only update your own reviews" });
        }

        // Prevent changing reviewer info
        delete updateData.reviewerEmail;
        delete updateData.reviewerName;

        const result = await reviewsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData },
        );

        res.send(result);
      },
    );

    // Delete review (users can only delete their own reviews)
    app.delete(
      "/api/v1/reviews/:id",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const id = req.params.id;

        // Find the review first to check ownership
        const review = await reviewsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Check ownership: users can only delete their own reviews
        if (
          req.user.role !== "admin" &&
          review.reviewerEmail !== req.user.email
        ) {
          return res
            .status(403)
            .send({ message: "You can only delete your own reviews" });
        }

        const result = await reviewsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      },
    );

    // =======================
    // 5. FAVORITES API
    // =======================
    // Get favorites meals (users can only see their own favorites)
    app.get(
      "/api/v1/favorites",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const favorites = await favoritesCollection
          .find({ userEmail: req.user.email })
          .sort({ addedTime: -1 })
          .toArray();
        res.send({ favorites });
      },
    );

    // Add to favorites (favorites are automatically linked to the authenticated user)
    app.post(
      "/api/v1/favorites",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const { mealId } = req.body;

        // Validate required field
        if (!mealId) {
          return res
            .status(400)
            .send({ message: "Missing required field: mealId" });
        }

        // Check if already in favorites
        const exists = await favoritesCollection.findOne({
          userEmail: req.user.email,
          mealId: mealId,
        });

        if (exists) {
          return res
            .status(400)
            .send({ message: "This meal is already in your favorites" });
        }

        // Get meal details to include in favorite
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(mealId),
        });
        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        // Create favorite with required data structure
        const newFavorite = {
          userEmail: req.user.email,
          mealId: mealId,
          mealName: meal.foodName,
          chefId: meal.chefId,
          chefName: meal.chefName,
          price: meal.price,
          addedTime: new Date().toISOString(),
        };

        const result = await favoritesCollection.insertOne(newFavorite);
        res.send(result);
      },
    );

    // Remove from favorites (users can only remove their own favorites)
    app.delete(
      "/api/v1/favorites/:id",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const id = req.params.id;

        // Find the favorite first to check ownership
        const favorite = await favoritesCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!favorite) {
          return res.status(404).send({ message: "Favorite not found" });
        }

        // Check ownership: users can only delete their own favorites
        if (
          req.user.role !== "admin" &&
          favorite.userEmail !== req.user.email
        ) {
          return res
            .status(403)
            .send({ message: "You can only remove your own favorites" });
        }

        const result = await favoritesCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      },
    );

    // =======================
    // 6. REQUESTS API (Chef/Admin requests)
    // =======================
    // Get all requests (Admin only)
    app.get("/api/v1/requests", auth("admin"), async (req, res) => {
      const requests = await requestsCollection
        .find()
        .sort({ requestTime: -1 })
        .toArray();
      res.send({ requests });
    });

    // Create request (request is automatically linked to the authenticated user)
    app.post(
      "/api/v1/requests",
      auth("user", "chef", "admin"),
      async (req, res) => {
        const requestData = req.body;

        // Force userEmail to be the authenticated user's email
        const newRequest = {
          ...requestData,
          userEmail: req.user.email,
          userName: req.user.name,
          requestTime: new Date().toISOString(),
          requestStatus: "pending",
        };

        // Check if user already has a pending request
        const existingRequest = await requestsCollection.findOne({
          userEmail: req.user.email,
          requestStatus: "pending",
        });

        if (existingRequest) {
          return res
            .status(400)
            .send({ message: "You already have a pending request" });
        }

        const result = await requestsCollection.insertOne(newRequest);
        res.send(result);
      },
    );

    // Approve request (Admin only) - handles both chef and admin requests
    app.patch(
      "/api/v1/requests/:id/approve",
      auth("admin"),
      async (req, res) => {
        const id = req.params.id;

        // Find the request
        const request = await requestsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!request) {
          return res.status(404).send({ message: "Request not found" });
        }

        // Check if already processed
        if (request.requestStatus !== "pending") {
          return res
            .status(400)
            .send({ message: "This request has already been processed" });
        }

        // Find the user who made the request
        const user = await usersCollection.findOne({
          email: request.userEmail,
        });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // Prepare user update based on request type
        let userUpdate = {};

        if (request.requestType === "chef") {
          // Generate unique ChefId: "chef-" + random 4-digit number
          const chefId = `chef-${Math.floor(1000 + Math.random() * 9000)}`;
          userUpdate = {
            role: "chef",
            chefId: chefId,
          };
        } else if (request.requestType === "admin") {
          userUpdate = {
            role: "admin",
          };
        }

        // Update user role and chefId (if chef)
        await usersCollection.updateOne(
          { email: request.userEmail },
          { $set: userUpdate },
        );

        // Update request status to approved
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { requestStatus: "approved" } },
        );

        res.send({
          message: `Request approved. User is now a ${request.requestType}.`,
          ...(request.requestType === "chef" && { chefId: userUpdate.chefId }),
        });
      },
    );

    // Reject request (Admin only)
    app.patch(
      "/api/v1/requests/:id/reject",
      auth("admin"),
      async (req, res) => {
        const id = req.params.id;

        // Find the request
        const request = await requestsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!request) {
          return res.status(404).send({ message: "Request not found" });
        }

        // Check if already processed
        if (request.requestStatus !== "pending") {
          return res
            .status(400)
            .send({ message: "This request has already been processed" });
        }

        // Update request status to rejected (user role does NOT change)
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { requestStatus: "rejected" } },
        );

        res.send({ message: "Request rejected." });
      },
    );

    // =======================
    // 7. ADMIN STATISTICS API
    // =======================
    app.get("/api/v1/admin/statistics", auth("admin"), async (req, res) => {
      const totalUsers = await usersCollection.countDocuments();
      const totalChefs = await usersCollection.countDocuments({ role: "chef" });
      const totalMeals = await mealsCollection.countDocuments();
      const pendingOrders = await ordersCollection.countDocuments({
        orderStatus: "pending",
      });
      const deliveredOrders = await ordersCollection.countDocuments({
        orderStatus: "delivered",
      });

      // Calculate total payments (sum of paid orders)
      const paidOrders = await ordersCollection
        .find({ paymentStatus: "paid" })
        .toArray();
      const totalPayments = paidOrders.reduce((sum, order) => {
        return sum + order.price * order.quantity;
      }, 0);

      res.send({
        totalUsers,
        totalChefs,
        totalMeals,
        pendingOrders,
        deliveredOrders,
        totalPayments,
      });
    });

    // =======================
    // 8. PAYMENT API (Stripe)
    // =======================
    // Create Stripe checkout session
    app.post(
      "/api/v1/payments/create-session",
      auth("user", "chef", "admin"),
      async (req, res) => {
        try {
          const { orderId } = req.body;
          // Find the order
          const order = await ordersCollection.findOne({
            _id: new ObjectId(orderId),
          });
          if (!order) {
            return res.status(404).send({ message: "Order not found" });
          }
          // Check ownership - only order owner can pay
          if (order.userEmail !== req.user.email) {
            return res
              .status(403)
              .send({ message: "You can only pay for your own orders" });
          }
          if (order.orderStatus !== "accepted") {
            return res
              .status(400)
              .send({ message: "You can only pay for accepted orders" });
          }
          if (order.paymentStatus === "paid") {
            return res
              .status(400)
              .send({ message: "This order has already been paid" });
          }
          // Create Stripe checkout session
          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [
              {
                price_data: {
                  currency: "usd",
                  product_data: {
                    name: order.mealName,
                    description: `Order from ${order.chefName}`,
                  },
                  unit_amount: Math.round(order.price * 100),
                },
                quantity: order.quantity,
              },
            ],
            mode: "payment",
            success_url: `${process.env.SERVER_URL}/api/v1/payments/verify?session_id={CHECKOUT_SESSION_ID}&order_id=${orderId}`,
            cancel_url: `${process.env.CLIENT_URL}/dashboard/my-orders?payment=cancelled`,
            metadata: {
              orderId: orderId,
              userEmail: req.user.email,
            },
          });
          res.send({ url: session.url, sessionId: session.id });
        } catch (error) {
          console.error("Stripe error:", error);
          res.status(500).send({
            message: "Payment session creation failed",
            error: error.message,
          });
        }
      },
    );

    // Verify payment and redirect to appropriate URL
    app.get("/api/v1/payments/verify", async (req, res) => {
      const successUrl = `${process.env.CLIENT_URL}/payment-success`;
      const failedUrl = `${process.env.CLIENT_URL}/payment-failed`;

      const { session_id: sessionId, order_id: orderId } = req.query;

      if (!sessionId || !orderId) {
        return res.redirect(`${failedUrl}?error=missing_parameters`);
      }

      // Start a session for transaction
      const dbSession = client.startSession();

      try {
        // Retrieve session from Stripe
        const stripeSession =
          await stripe.checkout.sessions.retrieve(sessionId);

        if (stripeSession.payment_status === "paid") {
          // Find the order
          const order = await ordersCollection.findOne({
            _id: new ObjectId(orderId),
          });

          if (!order) {
            return res.redirect(`${failedUrl}?error=order_not_found`);
          }

          // Verify order matches session metadata
          if (stripeSession.metadata.orderId !== orderId) {
            return res.redirect(`${failedUrl}?error=order_mismatch`);
          }

          // Start transaction
          dbSession.startTransaction();

          // Update order payment status
          await ordersCollection.updateOne(
            { _id: new ObjectId(orderId) },
            { $set: { paymentStatus: "paid" } },
            { session: dbSession },
          );

          // Save payment history
          const paymentRecord = {
            orderId: orderId,
            userEmail: stripeSession.metadata.userEmail,
            mealName: order.mealName,
            amount: order.price * order.quantity,
            currency: "usd",
            stripeSessionId: sessionId,
            stripePaymentIntent: stripeSession.payment_intent,
            paymentStatus: "completed",
            paymentTime: new Date().toISOString(),
          };

          await paymentsCollection.insertOne(paymentRecord, {
            session: dbSession,
          });

          // Commit the transaction
          await dbSession.commitTransaction();

          // Redirect to success page
          return res.redirect(successUrl);
        }
        return res.redirect(failedUrl);
      } catch (error) {
        // Rollback the transaction on error
        await dbSession.abortTransaction();
        console.error("Payment verification error:", error);
        return res.redirect(failedUrl);
      } finally {
        // End the session
        await dbSession.endSession();
      }
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
}

run().catch(console.dir);

app.get("/", (_req, res) => {
  res.status(200).send({
    status: "success",
    message: "Local Chef Bazaar Server Running",
    timestamp: new Date().toISOString(),
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
