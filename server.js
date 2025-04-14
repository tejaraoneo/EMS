const express = require("express");
const { ApolloServer } = require("apollo-server-express");
const cors = require("cors");
const jwt = require("jsonwebtoken"); // Import jsonwebtoken
const typeDefs = require("./schema");
const resolvers = require("./resolvers");
const restRoutes = require("./restRoutes");
const db = require("./db"); // Import db for querying user data

const startServer = async () => {
  const app = express();

  // Enable CORS for all routes
  app.use(cors());

  // Add middleware to parse JSON bodies
  app.use(express.json());

  // Authentication Middleware
  const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Expecting "Bearer <token>"
    if (!token) {
      req.user = null; // No user if no token
      return next();
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "your_secret_key"); // Use env variable for secret
      const [userRows] = await db.query(`
        SELECT u.user_id, u.tenant_id, u.role_id, r.role_name, GROUP_CONCAT(p.action) AS permissions
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN permissions p ON r.role_id = p.role_id
        WHERE u.user_id = ?
        GROUP BY u.user_id, u.tenant_id, u.role_id, r.role_name
      `, [decoded.user_id]);


      if (userRows.length === 0) {
        throw new Error("User not found.");
      }

      req.user = {
        user_id: userRows[0].user_id,
        tenant_id: userRows[0].tenant_id,
        role_id: userRows[0].role_id,
        role_name: userRows[0].role_name,
        permissions: userRows[0].permissions ? userRows[0].permissions.split(",") : [],
      };
      next();
    } catch (error) {
      console.error("Authentication error:", error);
      req.user = null; // Proceed without user context if token is invalid
      next();
    }
  };

  // Apply the authentication middleware
  app.use(authMiddleware);

  // Use REST routes
  app.use("/api", restRoutes);

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: ({ req }) => ({
      user: req.user, // Pass authenticated user to resolvers
    }),
  });

  await server.start();
  server.applyMiddleware({ app });

  const PORT = 4000;
  app.listen(PORT, () => {
    console.log(`🚀 Server ready at http://localhost:${PORT}/graphql`);
    console.log(`REST API ready at http://localhost:${PORT}/api`);
  });
};

startServer().catch((error) => {
  console.error("Failed to start server:", error);
});