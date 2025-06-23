// Load environment variables from .env file
import dotenv from "dotenv";
import express, { json } from "express";
dotenv.config();

// Import required modules
import admin from "firebase-admin";
import bodyParser from "body-parser";
import cors from "cors";
import md5 from "md5";
import jwt from "jsonwebtoken";
import pkg from "pg";
const { Pool } = pkg;
import { v4 as uuidv4 } from "uuid";
import { Resend } from "resend";
import crypto from "crypto";
import { sendPushNotification } from './SendNotification.js'; // Import the push notification function

const { verify, sign } = jwt;

// Initialize Express app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Store tokens in memory (use a database in production)
let pushTokens = [];
 
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Set up PostgreSQL connection pool using environment variables
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
});

// Resend mail service initialization
let resendPasswordClient;
let resendEmailClient;
try {
    console.log("RESEND_PASSWORD_API_KEY:", process.env.RESEND_PASSWORD_API_KEY ? "Set" : "Not set");
    resendPasswordClient = new Resend(process.env.RESEND_PASSWORD_API_KEY);
    console.log("Resend client initialized:", resendPasswordClient);
} catch (error) {
    console.error("Failed to initialize Resend:", error.message);
    process.exit(1); // Exit if Resend initialization fails
}

try {
    console.log("RESEND_EMAIL_API_KEY:", process.env.RESEND_EMAIL_API_KEY ? "Set" : "Not set");
    resendEmailClient = new Resend(process.env.RESEND_EMAIL_API_KEY);
    console.log("Resend client initialized:", resendEmailClient);
} catch (error) {
    console.error("Failed to initialize Resend:", error.message);
    process.exit(1); // Exit if Resend initialization fails
}

// Enable CORS for all origins and specify allowed methods and headers
app.use(cors({ origin: "*", methods: "GET,POST,PUT,DELETE", allowedHeaders: "Content-Type,Authorization" }));

// Parse incoming JSON requests
app.use(json());

// In-memory store for verification tokens (Map: shortToken -> { jwt, expiresAt, type, value })
const verificationTokens = new Map();

// Cleanup expired tokens every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [shortToken, { expiresAt }] of verificationTokens.entries()) {
        if (now > expiresAt) {
            verificationTokens.delete(shortToken);
        }
    }
}, 5 * 60 * 1000); // 5 minutes

// Generate a 6-character alphanumeric token
const generateShortToken = () => {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let token;
    do {
        token = Array.from(
            crypto.randomBytes(6),
            byte => characters[byte % characters.length]
        ).join("");
    } while (verificationTokens.has(token)); // Ensure uniqueness
    return token;
};

// Send verification email with 6-character token
const sendPasswordVerificationEmail = async (to, token, changeType) => {
    const subject = `Verify Your ${changeType} Change`;
    const html = `
        <p>Please use the following 6-character token to verify your ${changeType.toLowerCase()} change:</p>
        <h3>${token}</h3>
        <p>This token will expire in 10 minutes.</p>
    `;
    try {
        await resendPasswordClient.emails.send({
            from: "onboarding@resend.dev",
            to,
            subject,
            html,
        });
        console.log(`Verification email sent to ${to} with token ${token} for ${changeType}`);
    } catch (error) {
        console.error(`Error sending ${changeType} verification email:`, error);
        throw error;
    }
};


// Send verification email with 6-character token
 // Send email verification with a simple, clean template and 6-character token
const sendEmailVerificationEmail = async (to, token, changeType) => {
    const subject = `Email Verification Required`;
    
    // Create a simpler but distinct HTML template for email verification
    const html = `
        <h2>Email Verification</h2>
        <p>Hello,</p>
        <p>Your verification code for ${changeType.toLowerCase()} is:</p>
        <div style="font-size: 24px; font-weight: bold; background-color: #f2f2f2; padding: 10px; margin: 15px 0; text-align: center; letter-spacing: 3px;">${token}</div>
        <p><strong>Important:</strong> This code will expire in 10 minutes.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <hr>
        <p style="font-size: 12px; color: #777;">This is an automated message.</p>
    `;

    try {
        const response = await resendEmailClient.emails.send({
            from: "noreply@yourdomain.com",
            to,
            subject,
            html,
        });
        
        console.log(`Email verification sent to ${to} with token ${token} for ${changeType}`);
        return true;
    } catch (error) {
        console.error(`Error sending email verification:`, error);
        throw error;
    }
};

// Function to hash passwords using MD5 (less secure than bcrypt, consider upgrading)
const hashPassword = (password) => md5(password);

// Middleware to authenticate users via JWT
const authenticateUser = (req, res, next) => {
    const requestId = uuidv4();
    try {
        console.log(`[${requestId}] Starting authentication...`);
        const authHeader = req.headers["authorization"];
        console.log(`[${requestId}] Authorization Header:`, authHeader);

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            console.log(`[${requestId}] No Bearer token found.`);
            return res.status(401).json({ message: "No token provided, access denied." });
        }

        const token = authHeader.split(" ")[1];
        console.log(`[${requestId}] Extracted Token:`, token);

        if (token === null || token === undefined || token === "null") {
            console.log(`[${requestId}] Token is null or invalid.`);
            return res.status(401).json({ message: "Invalid token: null value provided." });
        }

        const decoded = verify(token, process.env.JWT_SECRET);
        console.log(`[${requestId}] Decoded Token:`, decoded);

        req.userId = decoded.userId;
        console.log(`[${requestId}] Extracted User ID:`, req.userId);

        next();
    } catch (error) {
        console.error(`[${requestId}] JWT Verification Error:`, error.name, error.message);
        if (error.name === "JsonWebTokenError") {
            return res.status(403).json({ message: "Invalid or malformed token." });
        } else if (error.name === "TokenExpiredError") {
            return res.status(403).json({ message: "Token has expired." });
        }
        return res.status(403).json({ message: "Authentication failed." });
    }
};

// Helper function to send notifications to specific users
const notifyUsers = async (userIds, title, body, data = {}) => {
    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        console.log('No user IDs provided for notification');
        return;
    }
    try {
        const query = 'SELECT device_token FROM device_tokens WHERE user_id = ANY($1)';
        const result = await pool.query(query, [userIds]);
        const tokens = result.rows.map(row => row.device_token);
        if (tokens.length === 0) {
            console.log('No device tokens found for users:', userIds);
            return;
        }
        await sendPushNotification(tokens, title, body, data);
        console.log('Notifications sent to users:', userIds);
    } catch (error) {
        console.error('Error sending notifications to users:', userIds, error.message);
    }
};

// // Function to get all checklist records
// const createGetRecordsFunction = async () => {
//   await pool.query(`
//   CREATE OR REPLACE FUNCTION get_checklist_records()
// RETURNS TABLE (
//   id INTEGER,
//   user_id INTEGER,
//   location_id INTEGER,
//   data JSONB,
//   created_at TIMESTAMP,
//   username TEXT
// ) AS $$
// BEGIN
//   RETURN QUERY
//   SELECT
//     cr.id,
//     cr.user_id,
//     cr.location_id,
//     cr.data,
//     cr.created_at,
//     u.username
//   FROM checklist_records cr
//   JOIN users u ON cr.user_id = u.user_id
//   ORDER BY cr.created_at DESC;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Function to get all locations
// const createGetLocationsFunction = async () => {
//   await pool.query(`
//     CREATE OR REPLACE FUNCTION get_locations()
// RETURNS TABLE (
//   location_id INTEGER,
//   name TEXT,
//   region_id INTEGER
// ) AS $$
// BEGIN
//   RETURN QUERY
//   SELECT
//     l.location_id,
//     l.name,
//     l.region_id
//   FROM locations l
//   ORDER BY l.location_id;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Function to get all categories
// const createGetCategoriesFunction = async () => {
//   await pool.query(`
//     CREATE OR REPLACE FUNCTION get_categories()
// RETURNS TABLE (
//   category_id INTEGER,
//   name TEXT,
//   description TEXT
// ) AS $$
// BEGIN
//   RETURN QUERY
//   SELECT
//     c.category_id,
//     c.name,
//     c.description
//   FROM categories c
//   ORDER BY c.name;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Function to get all checklist items
// const createGetChecklistItemsFunction = async () => {
//   await pool.query(`
//    CREATE OR REPLACE FUNCTION get_checklist_items()
// RETURNS TABLE (
//   item_id INTEGER,
//   category_id INTEGER,
//   name TEXT,
//   description TEXT
// ) AS $$
// BEGIN
//   RETURN QUERY
//   SELECT
//     ci.item_id,
//     ci.category_id,
//     ci.name,
//     ci.description
//   FROM checklist_items ci
//   ORDER BY ci.category_id, ci.name;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Function to save checklist responses
// const createSaveChecklistFunction = async () => {
//   await pool.query(`
//     CREATE OR REPLACE FUNCTION save_checklist(
//   p_user_id INTEGER,
//   p_location_id INTEGER,
//   p_username TEXT,
//   p_responses JSONB
// )
// RETURNS VOID AS $$
// DECLARE
//   response JSONB;
//   item_id INTEGER;
//   status TEXT;
//   comment TEXT;
//   category_name TEXT;
//   item_description TEXT;
//   today_date DATE := CURRENT_DATE;
// BEGIN
//   -- Check if location has submissions for today
//   IF EXISTS (
//     SELECT 1
//     FROM checklist_records cr
//     WHERE cr.location_id = p_location_id
//     AND DATE(cr.created_at) = today_date
//     AND cr.data->>'categoryName' IN (
//       SELECT name FROM categories
//     )
//     GROUP BY cr.location_id
//     HAVING COUNT(DISTINCT cr.data->>'categoryName') = (SELECT COUNT(*) FROM categories)
//   ) THEN
//     RAISE EXCEPTION 'Location % has already been fully submitted for today', p_location_id;
//   END IF;

//   -- Loop through responses
//   FOR response IN SELECT jsonb_array_elements(p_responses)
//   LOOP
//     item_id := (response->>'item_id')::INTEGER;
//     status := response->>'status';
//     comment := response->>'comment';

//     -- Get category name and item description
//     SELECT c.name, ci.description
//     INTO category_name, item_description
//     FROM checklist_items ci
//     JOIN categories c ON ci.category_id = c.category_id
//     WHERE ci.item_id = item_id;

//     -- Insert record
//     INSERT INTO checklist_records (
//       user_id,
//       location_id,
//       data,
//       created_at,
//       username
//     ) VALUES (
//       p_user_id,
//       p_location_id,
//       jsonb_build_object(
//         'itemId', item_id,
//         'status', status,
//         'comment', comment,
//         'categoryName', category_name,
//         'itemDescription', item_description
//       ),
//       CURRENT_TIMESTAMP,
//       p_username
//     );
//   END LOOP;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Function to get user-specific records
// const createGetUserRecordsFunction = async () => {
//   await pool.query(`
//     CREATE OR REPLACE FUNCTION get_user_records(p_user_id INTEGER)
// RETURNS TABLE (
//   id INTEGER,
//   user_id INTEGER,
//   location_id INTEGER,
//   location_name TEXT,
//   data JSONB,
//   created_at TIMESTAMP
// ) AS $$
// BEGIN
//   RETURN QUERY
//   SELECT
//     cr.id,
//     cr.user_id,
//     cr.location_id,
//     l.name AS location_name,
//     cr.data,
//     cr.created_at
//   FROM checklist_records cr
//   JOIN locations l ON cr.location_id = l.location_id
//   WHERE cr.user_id = p_user_id
//   ORDER BY cr.created_at DESC;
// END;
// $$ LANGUAGE plpgsql;
//   `);
// };

// // Initialize stored functions
// const initializeFunctions = async () => {
//   try {
//     await createGetRecordsFunction();
//     await createGetLocationsFunction();
//     await createGetCategoriesFunction();
//     await createGetChecklistItemsFunction();
//     await createSaveChecklistFunction();
//     await createGetUserRecordsFunction();
//     console.log('Stored functions initialized successfully');
//   } catch (error) {
//     console.error('Error initializing stored functions:', error.message);
//   }
// };

// // Call initialization (run once during server startup)
// initializeFunctions().catch(err => console.error('Initialization error:', err));

// Add root route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the IT Admin Backend!' });
});

// // Login route to authenticate users
// app.post("/login", async (req, res) => {
//     const { username, password } = req.body;

//     try {
//         const hashedPassword = hashPassword(password);
//         console.log(`Hashed Password: ${hashedPassword}`);

//         const query = `SELECT login('{"username": "${username}", "password": "${hashedPassword}"}');`;
//         console.log(`QUERY: ${query}\n`);
//         const result = await pool.query(query);

//         if (result.rows.length === 0) {
//             return res.status(401).json({ message: "Invalid credentials" });
//         }

//         const user = result.rows[0];
//         console.log(user.login);
//         const loginResult = JSON.parse(user.login);
//         const passwordMatch = loginResult?.success;

//         if (!passwordMatch) {
//             return res.status(401).json({ message: "Invalid credentials", success: false });
//         }

//         const token = sign({ userId: loginResult.data[0].id, username: loginResult.data[0].username }, process.env.JWT_SECRET, { expiresIn: "1h" });

//         res.json({ message: "Login successful", token, success: true });
//     } catch (error) {
//         console.error("Login error:", error);
//         res.status(500).json({ message: "Server error" });
//     }
// });

// Updated Login route to authenticate users and register push token
app.post("/login", async (req, res) => {
    const { username, password, pushToken } = req.body; // Added pushToken parameter
     
    try {
        const hashedPassword = hashPassword(password);
        console.log(`Hashed Password: ${hashedPassword}`);
         
        const query = `SELECT login('{"username": "${username}", "password": "${hashedPassword}"}');`;
        console.log(`QUERY: ${query}\n`);
        const result = await pool.query(query);
         
        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
         
        const user = result.rows[0];
        console.log(user.login);
        const loginResult = JSON.parse(user.login);
        const passwordMatch = loginResult?.success;
         
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid credentials", success: false });
        }
         
        const userId = loginResult.data[0].id;
        const userUsername = loginResult.data[0].username;
        
        const token = sign({ 
            userId: userId, 
            username: userUsername 
        }, process.env.JWT_SECRET, { expiresIn: "1h" });

        // Register push token if provided
        if (pushToken) {
            try {
                // Check if user already has a token registered
                const existingToken = await pool.query(
                    'SELECT id, device_token FROM device_tokens WHERE user_id = $1',
                    [userId]
                );

                if (existingToken.rows.length > 0) {
                    const existingRecord = existingToken.rows[0];
                    
                    // If token is different, update it
                    if (existingRecord.device_token !== pushToken) {
                        await pool.query(
                            'UPDATE device_tokens SET device_token = $1, updated_at = NOW() WHERE user_id = $2',
                            [pushToken, userId]
                        );
                        console.log('Updated push token for user:', userId);
                    } else {
                        console.log('Push token already up-to-date for user:', userId);
                    }
                } else {
                    // Insert new token
                    await pool.query(
                        'INSERT INTO device_tokens (device_token, user_id, created_at) VALUES ($1, $2, NOW())',
                        [pushToken, userId]
                    );
                    console.log('Registered new push token for user:', userId);
                }
            } catch (tokenError) {
                console.error('Error registering push token during login:', tokenError);
                // Don't fail login if push token registration fails
            }
        }
         
        res.json({ 
            message: "Login successful", 
            token, 
            success: true,
            userId: userId,
            username: userUsername
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
});



// Route to fetch user profile (requires authentication)
app.get("/user/profile", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        const query = `
            SELECT 
                u.id,
                u.username, 
                u.first_name, 
                u.surname, 
                u.email, 
                u.phone, 
                u.role,
                r.region_name
            FROM users u
            LEFT JOIN regions r ON u.region = r.id
            WHERE u.id = $1;
        `;
        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const userProfile = result.rows[0];
        res.json({
            id: userProfile.id,
            username: userProfile.username,
            first_name: userProfile.first_name,
            surname: userProfile.surname,
            email: userProfile.email,
            phone: userProfile.phone,
            role: userProfile.role,
            region_name: userProfile.region_name,
        });
    } catch (error) {
        console.error("Error fetching user profile:", error);
        res.status(500).json({ message: "Error fetching user profile" });
    }
});

// Route to fetch tickets opened by the user
app.get("/user/tickets", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        const query = `
            SELECT 
                t.id,
                t.code,
                t.complainant_name,
                t.date_created,
                t.date_assigned,
                t.details,
                t.status_id,
                s.status_name AS status
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.open_id = $1
            ORDER BY t.date_created DESC;
        `;
        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No tickets found for this user." });
        }

        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching user tickets:", error);
        res.status(500).json({ message: "Error fetching user tickets" });
    }
});

// Route to fetch details of a specific ticket by ID
app.get("/tickets/details/:id", authenticateUser, async (req, res) => {
    try {
        const { id } = req.params;
        const query = `
            SELECT 
                t.id, t.code, t.subject, t.details, t.status_id, s.status_name
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.id = $1;
        `;
        const result = await pool.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Ticket not found" });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error("Error fetching ticket details:", error);
        res.status(500).json({ message: "Error fetching ticket details" });
    }
});

// Route to fetch tickets by department ID
app.get("/tickets/by-department/:deptId", authenticateUser, async (req, res) => {
    try {
        const { deptId } = req.params;
        const query = `
            SELECT 
                t.id, t.code, t.subject, t.date_created, t.status_id, s.status_name
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.department_id = $1;
        `;
        const result = await pool.query(query, [deptId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No tickets found for this department" });
        }

        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching tickets by department:", error);
        res.status(500).json({ message: "Error fetching tickets by department" });
    }
});

// Route to fetch ticket logs by region ID
app.get("/tickets/logs/:regionId", authenticateUser, async (req, res) => {
    try {
        const { regionId } = req.params;
        const query = `
            SELECT 
                tl.log_id, tl.ticket_id, tl.action, tl.timestamp
            FROM ticket_logs tl
            JOIN tickets t ON tl.ticket_id = t.id
            WHERE t.region_id = $1;
        `;
        const result = await pool.query(query, [regionId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No logs found for this region" });
        }

        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching ticket logs:", error);
        res.status(500).json({ message: "Error fetching ticket logs" });
    }
});

// Route to fetch user's first name for greeting
app.get("/user/greeting", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        const query = "SELECT first_name FROM users WHERE id = $1";
        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ first_name: result.rows[0].first_name });
    } catch (error) {
        console.error("Error fetching user greeting:", error);
        res.status(500).json({ message: "Error fetching user greeting" });
    }
});

// Route to fetch ticket status counts for the user
app.get("/tickets/status", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;

        const query = `
            SELECT
                COUNT(*) FILTER (WHERE status_id = 2) AS pending_count,
                COUNT(*) FILTER (WHERE status_id = 3) AS on_hold_count,
                COUNT(*) FILTER (WHERE status_id = 4) AS solved_count,
                COUNT(*) FILTER (WHERE status_id = 5) AS closed_count
            FROM tickets
            WHERE assigned_userid = $1 OR open_id = $1;
        `;
        const result = await pool.query(query, [userId]);
        console.log("Raw query result:", result.rows[0]);

        const pendingCount = parseInt(result.rows[0].pending_count, 10) || 0;
        const onHoldCount = parseInt(result.rows[0].on_hold_count, 10) || 0;
        const solvedCount = parseInt(result.rows[0].solved_count, 10) || 0;
        const closedCount = parseInt(result.rows[0].closed_count, 10) || 0;

        console.log("Parsed counts:", { pendingCount, onHoldCount, solvedCount, closedCount });

        res.json([
            { title: "Pending", number: pendingCount, color: "#FF6B6B" },
            { title: "On Hold", number: onHoldCount, color: "#FFD93D" },
            { title: "Solved", number: solvedCount, color: "#4D96FF" },
            { title: "Closed", number: closedCount, color: "#6BCB77" }
        ]);
    } catch (error) {
        console.error("Error fetching ticket status counts:", error);
        res.status(500).json({ message: "Error fetching ticket status counts" });
    }
});

// Route to fetch priority analytics for the user
app.get("/tickets/priority", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        const query = `
            SELECT 
                p.priority_name AS priority,
                COUNT(t.id) AS count
            FROM tickets t
            LEFT JOIN priority p ON t.priority_id = p.id
            WHERE t.assigned_userid = $1 OR t.open_id = $1
            GROUP BY p.priority_name;
        `;
        const result = await pool.query(query, [userId]);

        const data = result.rows.reduce((acc, row) => {
            acc[row.priority || "Unknown"] = Number(row.count) || 0;
            return acc;
        }, { Low: 0, Medium: 0, High: 0, Urgent: 0 });

        res.json(data);
    } catch (error) {
        console.error("Error fetching priority analytics:", error);
        res.status(500).json({ message: "Error fetching priority analytics" });
    }
});

// Route for tickets created by the user
app.get("/user/tickets/created", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        console.log("Fetching user details and created tickets", { userId });
// fetch for first_name and last_name
        const userQuery = `
            SELECT first_name, surname 
            FROM users 
            WHERE id = $1;
        `;
        const userResult = await pool.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            console.log("User not found", { userId });
            return res.status(404).json({ message: "User not found." });
        }

        const { first_name, surname } = userResult.rows[0];
        const creatorName = `${first_name} ${surname}`; // e.g., "John Doe"
// check for user_id = open_id
        const ticketsQuery = `
            SELECT
                t.id,
                t.code,
                t.complainant_name,
                t.date_created,
                t.date_assigned,
                t.details,
                t.status_id,
                s.status_name AS status
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.open_id = $1 AND t.created_by = $2
            ORDER BY t.date_created DESC;
        `;
        
        const ticketsResult = await pool.query(ticketsQuery, [userId, creatorName]);
        console.log("Tickets fetched", { ticketCount: ticketsResult.rows.length });

        if (ticketsResult.rows.length === 0) {
            return res.status(200).json([]); // Return empty array (RESTful)
        }

        res.json(ticketsResult.rows);
    } catch (error) {
        console.error("Error fetching user-created tickets", { 
            userId: req.userId, 
            error: error.message, 
            stack: error.stack 
        });
        res.status(500).json({ message: "Error fetching user tickets" });
    }
});


// Route for tickets assigned to the user
app.get("/user/tickets/assigned", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        console.log("Entering /user/tickets/assigned route", { userId, path: req.path });
        console.log("Fetching assigned tickets", { userId, path: req.path });

        const query = `
            SELECT
                t.id,
                t.code,
                t.complainant_name,
                t.date_created,
                t.date_assigned,
                t.details,
                t.status_id,
                s.status_name AS status
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.assigned_userid = $1
            ORDER BY t.date_created DESC;
        `;
        console.log("Executing query for assigned tickets", { userId });
        const result = await pool.query(query, [userId]);
        console.log("Query result for assigned tickets", { ticketCount: result.rows.length, tickets: result.rows });
        console.log("Assigned tickets fetched", { userId, ticketCount: result.rows.length });

        if (result.rows.length === 0) {
            console.log("No assigned tickets found", { userId });
            return res.status(404).json({ message: "No tickets assigned to this user." });
        }

        console.log("Sending response with assigned tickets", { ticketCount: result.rows.length });
        res.json(result.rows);
    } catch (error) {
        console.error("Error in /user/tickets/assigned route", { userId: req.userId, error: error.message, stack: error.stack });
        console.error("Error fetching assigned tickets", { userId: req.userId, error: error.message, stack: error.stack });
        res.status(500).json({ message: "Error fetching assigned tickets" });
    }
});

app.get("/tickets/trends", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        const query = `
            SELECT 
                EXTRACT(WEEK FROM date_created) AS week,
                COUNT(*) FILTER (WHERE status_id = 1) AS pending,
                COUNT(*) FILTER (WHERE status_id = 4) AS solved
            FROM tickets
            WHERE assigned_userid = $1 OR open_id = $1
            GROUP BY EXTRACT(WEEK FROM date_created)
            ORDER BY week ASC;
        `;
        const result = await pool.query(query, [userId]);

        res.json({
            weeks: result.rows.map(row => `Week ${row.week}`),
            pending: result.rows.map(row => Number(row.pending) || 0),
            solved: result.rows.map(row => Number(row.solved) || 0),
        });
    } catch (error) {
        console.error("Error fetching ticket trends:", error);
        res.status(500).json({ message: "Error fetching ticket trends" });
    }
});


// Route to submit a new ticket
app.post('/submit-ticket', async (req, res) => {
    const { name, division, phoneNumber, office, priority, subject, details, staffId, regionId } = req.body;
    if (!name || !division || !phoneNumber || !office || !priority || !subject || !details) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    if (staffId && typeof staffId !== 'string') {
        return res.status(400).json({ success: false, message: 'Staff ID must be a string' });
    }
    if (regionId && (!Number.isInteger(regionId) || regionId <= 0)) {
        return res.status(400).json({ success: false, message: 'Region ID must be a positive integer' });
    }
    try {
        let userId = null;
        if (req.headers.authorization) {
            try {
                const authHeader = req.headers.authorization;
                if (authHeader.startsWith('Bearer ')) {
                    const token = authHeader.split(' ')[1];
                    const decoded = verify(token, process.env.JWT_SECRET);
                    userId = decoded.userId;
                }
            } catch (error) {
                console.warn('Authentication attempt failed, proceeding as unauthenticated:', error.message);
            }
        }
        const defaultRegionId = 1;
        const finalRegionId = regionId || defaultRegionId;
        const ticketDetails = {
            staff_id: staffId || null,
            region_id: regionId === 'greater_accra' ? 1 : regionId === 'ashanti' ? 2 : regionId === 'western' ? 3 : regionId === 'eastern' ? 4 : regionId === 'central' ? 5 : regionId === 'volta' ? 6 : regionId === 'northern' ? 7 : regionId === 'upper_east' ? 8 : regionId === 'upper_west' ? 9 : 1,
            division_id: division === 'lvd' ? 1 : division === 'pvlmd' ? 2 : division === 'lrd' ? 3 : division === 'smd' ? 4 : division === 'corporate' ? 5 : 5,
            priority_id: priority === 'urgent' ? 1 : priority === 'high' ? 2 : priority === 'medium' ? 3 : 4,
            is_assigned: 0,
            assigned_userid: null,
            date_assigned: 'N/A',
            department_id: null,
            subject,
            details,
            complainant_name: name,
            complainant_number: phoneNumber,
            complainant_office: office,
            status_id: 1,
            open_id: userId,
            pin: Math.floor(1000 + Math.random() * 9000),
            created_by: name,
            date_created: new Date().toISOString(),
        };
        const jsonTicketDetails = JSON.stringify(ticketDetails);
        const query = `SELECT public.ticket_insert($1::text) AS result;`;
        console.log('Submitting ticket with JSON:', jsonTicketDetails);
        const result = await pool.query(query, [jsonTicketDetails]);
        const insertResult = result.rows[0].result;
        if (insertResult) {
            let verifyQuery;
            let verifyParams;
            if (userId) {
                verifyQuery = `
                    SELECT code
                    FROM public.tickets
                    WHERE open_id = $1
                    AND date_created = $2
                    AND subject = $3
                    LIMIT 1;
                `;
                verifyParams = [userId, ticketDetails.date_created, ticketDetails.subject];
            } else {
                verifyQuery = `
                    SELECT code
                    FROM public.tickets
                    WHERE open_id IS NULL
                    AND created_by = $1
                    AND date_created = $2
                    AND subject = $3
                    LIMIT 1;
                `;
                verifyParams = [ticketDetails.created_by, ticketDetails.date_created, ticketDetails.subject];
            }
            const verifyResult = await pool.query(verifyQuery, verifyParams);
            if (verifyResult.rows.length > 0) {
                const ticketCode = verifyResult.rows[0].code;
                console.log(`New ticket submitted successfully. Ticket Code: ${ticketCode}`);
                // Notify ticket creator if authenticated
                if (userId) {
                    await notifyUsers([userId], 'New Ticket Created', `Your ticket ${ticketCode} has been created.`, { ticketId: ticketCode });
                }
                return res.status(201).json({
                    success: true,
                    message: 'Ticket submitted successfully',
                    ticketCode,
                });
            } else {
                console.error('Ticket insertion failed: No ticket found in database');
                return res.status(500).json({
                    success: false,
                    message: 'Failed to submit ticket: Ticket not found in database',
                });
            }
        } else {
            console.error('Ticket insertion failed: Function returned false');
            return res.status(500).json({
                success: false,
                message: 'Failed to submit ticket: Database function failed',
            });
        }
    } catch (error) {
        console.error('Error submitting ticket:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message,
        });
    }
});

// // Route to fetch recent notifications
// app.get("/notifications", authenticateUser, async (req, res) => {
//     try {
//         const query = `
//             SELECT message, created_at
//             FROM notifications
//             ORDER BY created_at DESC
//             LIMIT 10;
//         `;
//         const result = await pool.query(query);
//         res.json(result.rows);
//     } catch (error) {
//         console.error("Error fetching notifications:", error);
//         res.status(500).json({ message: "Error fetching notifications" });
//     }
// });

// app.post('/sendPushNotification', authenticateUser, async (req, res) => {
//   const { userIds, ticketId, title, body } = req.body;
//   if (!userIds || !Array.isArray(userIds) || !title || !body) {
//     return res.status(400).json({ message: 'Missing required fields: userIds, title, body' });
//   }
//   try {
//     const query = 'SELECT device_token FROM device_tokens WHERE user_id = ANY($1)';
//     const result = await pool.query(query, [userIds]);
//     const tokens = result.rows.map(row => row.device_token);
//     if (tokens.length === 0) {
//       return res.status(404).json({ message: 'No device tokens found' });
//     }
//  const message = {
//   notification: { title, body },
//   data: { ticketId: ticketId ? ticketId.toString() : '' },
//   android: { priority: 'high' },
//   tokens,
// };

// const response = await admin.messaging().sendEachForMulticast(message);
//     const insertPromises = userIds.map(userId =>
//   pool.query(
//     'INSERT INTO notifications (message, created_at, user_id) VALUES ($1, $2, $3)',
//     [`${title}: ${body}`, new Date(), userId]
//   )
// );
// await Promise.all(insertPromises);
//     res.status(200).json({ message: 'Notifications sent successfully', response });
//   } catch (error) {
//     console.error('Error sending notifications:', error);
//     res.status(500).json({ message: 'Error sending notifications', error: error.message });
//   }
// });

// Route to save device token
app.post('/save-device-token', authenticateUser, async (req, res) => {
    const { deviceToken } = req.body;
    const userId = req.userId;
    if (!deviceToken || typeof deviceToken !== 'string') {
        return res.status(400).json({ message: 'Invalid device token' });
    }
    try {
        const query = 'SELECT update_device_token($1, $2) AS result';
        const result = await pool.query(query, [userId, deviceToken]);
        if (result.rows[0].result) {
            return res.status(200).json({ message: 'Device token saved successfully' });
        }
        return res.status(500).json({ message: 'Failed to save device token' });
    } catch (error) {
        console.error('Error saving device token:', error);
        return res.status(500).json({ message: 'Error saving device token', error: error.message });
    }
});

// // Endpoint to register push token
// app.post('/register', (req, res) => {
//   const { token } = req.body;
//   if (token && !pushTokens.includes(token)) {
//     pushTokens.push(token);
//     console.log('Registered push token:', token);
//   }
//   res.send('Token registered');
// });

// // Unified endpoint to register or update push token
// app.post('/register', async (req, res) => {
//     try {
//       const { token, user_id } = req.body;
      
//       // Validate input
//       if (!token) {
//         return res.status(400).json({ 
//           error: 'Push token is required' 
//         });
//       }
      
//       if (!user_id) {
//         return res.status(400).json({ 
//           error: 'User ID is required' 
//         });
//       }
  
//       // Check if user already has a token registered
//       const existingToken = await db.query(
//         'SELECT id, device_token FROM device_tokens WHERE user_id = ?',
//         [user_id]
//       );
  
//       if (existingToken.length > 0) {
//         const existingRecord = existingToken[0];
        
//         // If token is the same, no need to update
//         if (existingRecord.device_token === token) {
//           console.log('Push token already up-to-date for user:', user_id);
//           return res.json({ 
//             message: 'Token already registered and up-to-date',
//             token_id: existingRecord.id,
//             action: 'no_change'
//           });
//         }
        
//         // Update existing token
//         await db.query(
//           'UPDATE device_tokens SET device_token = ?, updated_at = NOW() WHERE user_id = ?',
//           [token, user_id]
//         );
        
//         console.log('Updated push token for user:', user_id, 'Token ID:', existingRecord.id);
//         return res.json({ 
//           message: 'Token updated successfully',
//           token_id: existingRecord.id,
//           action: 'updated'
//         });
//       }
  
//       // Insert new token if user doesn't have one
//       const result = await db.query(
//         'INSERT INTO device_tokens (device_token, user_id, created_at) VALUES (?, ?, NOW())',
//         [token, user_id]
//       );
  
//       console.log('Registered new push token for user:', user_id, 'Token ID:', result.insertId);
      
//       res.status(201).json({ 
//         message: 'Token registered successfully',
//         token_id: result.insertId,
//         action: 'created'
//       });
  
//     } catch (error) {
//       console.error('Error processing push token:', error);
//       res.status(500).json({ 
//         error: 'Failed to process token' 
//       });
//     }
//   });

app.post('/register', async (req, res) => {
    try {
        const { token, user_id } = req.body;
        
        // Validate input
        if (!token) {
            return res.status(400).json({ 
                error: 'Push token is required' 
            });
        }
        
        if (!user_id) {
            return res.status(400).json({ 
                error: 'User ID is required' 
            });
        }

        // Check if user already has a token registered
        const existingToken = await pool.query(
            'SELECT id, device_token FROM device_tokens WHERE user_id = $1',
            [user_id]
        );

        if (existingToken.rows.length > 0) {
            const existingRecord = existingToken.rows[0];
            
            // If token is the same, no need to update
            if (existingRecord.device_token === token) {
                console.log('Push token already up-to-date for user:', user_id);
                return res.json({ 
                    message: 'Token already registered and up-to-date',
                    token_id: existingRecord.id,
                    action: 'no_change'
                });
            }
            
            // Update existing token
            await pool.query(
                'UPDATE device_tokens SET device_token = $1, updated_at = NOW() WHERE user_id = $2',
                [token, user_id]
            );
            
            console.log('Updated push token for user:', user_id, 'Token ID:', existingRecord.id);
            return res.json({ 
                message: 'Token updated successfully',
                token_id: existingRecord.id,
                action: 'updated'
            });
        }

        // Insert new token if user doesn't have one
        const result = await pool.query(
            'INSERT INTO device_tokens (device_token, user_id, created_at) VALUES ($1, $2, NOW()) RETURNING id',
            [token, user_id]
        );

        console.log('Registered new push token for user:', user_id, 'Token ID:', result.rows[0].id);
        
        res.status(201).json({ 
            message: 'Token registered successfully',
            token_id: result.rows[0].id,
            action: 'created'
        });

    } catch (error) {
        console.error('Error processing push token:', error);
        res.status(500).json({ 
            error: 'Failed to process token' 
        });
    }
});
  
  // Alternative approach using MySQL's ON DUPLICATE KEY UPDATE (if you have a unique constraint)
  /*
  app.post('/register', async (req, res) => {
    try {
      const { token, user_id } = req.body;
      
      // Validate input
      if (!token) {
        return res.status(400).json({ 
          error: 'Push token is required' 
        });
      }
      
      if (!user_id) {
        return res.status(400).json({ 
          error: 'User ID is required' 
        });
      }
  
      // Use INSERT ... ON DUPLICATE KEY UPDATE for MySQL
      // This requires a UNIQUE constraint on user_id column
      const result = await db.query(`
        INSERT INTO device_tokens (device_token, user_id, created_at) 
        VALUES (?, ?, NOW())
        ON DUPLICATE KEY UPDATE 
          device_token = VALUES(device_token),
          updated_at = NOW()
      `, [token, user_id]);
  
      const action = result.affectedRows === 1 ? 'created' : 'updated';
      const token_id = result.insertId || result.insertId;
      
      console.log(`${action} push token for user:`, user_id);
      
      res.status(action === 'created' ? 201 : 200).json({ 
        message: `Token ${action} successfully`,
        token_id: token_id,
        action: action
      });
  
    } catch (error) {
      console.error('Error processing push token:', error);
      res.status(500).json({ 
        error: 'Failed to process token' 
      });
    }
  });
  */

// Route to send push notifications to specific users
app.post('/send-notification', authenticateUser, async (req, res) => {
    const { userIds, title, body, ticketId } = req.body;
    if (!userIds || !Array.isArray(userIds) || !title || !body) {
        return res.status(400).json({ message: 'Missing required fields: userIds, title, body' });
    }
    try {
        const query = 'SELECT device_token FROM device_tokens WHERE user_id = ANY($1)';
        const result = await pool.query(query, [userIds]);
        const tokens = result.rows.map(row => row.device_token);
        if (tokens.length === 0) {
            return res.status(404).json({ message: 'No device tokens found for specified users' });
        }
        const data = ticketId ? { ticketId: ticketId.toString() } : {};
        await sendPushNotification(tokens, title, body, data);
        const insertPromises = userIds.map(userId =>
            pool.query(
                'INSERT INTO notifications (message, created_at, user_id) VALUES ($1, $2, $3)',
                [`${title}: ${body}`, new Date(), userId]
            )
        );
        await Promise.all(insertPromises);
        res.status(200).json({ message: 'Notifications sent successfully' });
    } catch (error) {
        console.error('Error sending notifications:', error);
        res.status(500).json({ message: 'Error sending notifications', error: error.message });
    }
});

// Route to fetch department-wise ticket counts (admin)
app.get("/tickets/department-counts-admin", authenticateUser, async (req, res) => {
    try {
        const query = `SELECT select_status_tickets_by_dept();`;
        const result = await pool.query(query);
        const jsonResult = JSON.parse(result.rows[0].select_status_tickets_by_dept);

        if (!jsonResult.success) {
            return res.status(500).json({ message: "Error fetching department counts from database" });
        }

        const data = {
            hardware_total_tickets: Number(jsonResult.hardware_total_tickets) || 0,
            software_total_tickets: Number(jsonResult.software_total_tickets) || 0,
            networking_total_tickets: Number(jsonResult.networking_total_tickets) || 0,
            corporate_total_tickets: Number(jsonResult.desktop_support_total_tickets) || 0,
        };

        res.json(data);
    } catch (error) {
        console.error("Error fetching department ticket counts:", error);
        res.status(500).json({ message: "Error fetching department ticket counts", error: error.message });
    }
});

// Route to fetch admin priority analytics
app.get("/tickets/priority-analytics-admin", authenticateUser, async (req, res) => {
    try {
        const query = `
            SELECT 
                p.priority_name AS priority,
                COUNT(t.id) AS count
            FROM tickets t
            LEFT JOIN priority p ON t.priority_id = p.id
            GROUP BY p.priority_name;
        `;
        const result = await pool.query(query);

        const data = result.rows.map(row => ({
            priority: row.priority || "Unknown",
            count: Number(row.count) || 0,
        }));
        res.json({ data });
    } catch (error) {
        console.error("Error fetching priority analytics:", error);
        res.status(500).json({ message: "Error fetching priority analytics", error: error.message });
    }
});

// Route to fetch admin weekly trends
app.get("/tickets/weekly-trends-admin", authenticateUser, async (req, res) => {
    try {
        const query = `SELECT select_status_tickets_by_dept_per_month();`;
        const result = await pool.query(query);
        const jsonResult = JSON.parse(result.rows[0].select_status_tickets_by_dept_per_month);

        if (!jsonResult.success) {
            return res.status(500).json({ message: "Error fetching weekly trends from database" });
        }

        const months = [
            "jan", "feb", "mar", "apr", "may", "jun",
            "jul", "aug", "sep", "oct", "nov", "dec"
        ];
        const data = months.map((month, index) => {
            const hardwarePending = Number(jsonResult[`hardware_${month}_count`]) || 0;
            const softwarePending = Number(jsonResult[`software_${month}_count`]) || 0;
            const networkingPending = Number(jsonResult[`networking_${month}_count`]) || 0;
            const desktopPending = Number(jsonResult[`desktop_support_${month}_count`]) || 0;

            return {
                week: index + 1,
                pending: hardwarePending + softwarePending + networkingPending + desktopPending,
                solved: 0
            };
        });

        res.json({ data });
    } catch (error) {
        console.error("Error fetching weekly trends:", error);
        res.status(500).json({ message: "Error fetching weekly trends", error: error.message });
    }
});

// Route to fetch ticket statistics for the user
app.get("/tickets/stats", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;

        // Query to fetch ticket statistics
        const statsQuery = `
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE DATE_PART('month', date_created::timestamp) = DATE_PART('month', CURRENT_DATE)) AS monthly,
                COUNT(*) FILTER (WHERE priority_id = 1) AS low,
                COUNT(*) FILTER (WHERE priority_id = 2) AS medium,
                COUNT(*) FILTER (WHERE priority_id = 3) AS high,
                COUNT(*) FILTER (WHERE priority_id = 4) AS urgent
            FROM tickets
            WHERE assigned_userid = $1 OR open_id = $1;
        `;
        const statsResult = await pool.query(statsQuery, [userId]);

        // Query to calculate average assignment rate
        const assignmentRateQuery = `
            WITH assignment_data AS (
                SELECT
                    COUNT(*) AS total_assigned_tickets,
                    MIN(date_assigned::timestamp) AS first_assignment_date,
                    MAX(date_assigned::timestamp) AS last_assignment_date
                FROM tickets
                WHERE assigned_userid = $1
            )
            SELECT
                total_assigned_tickets,
                DATE_PART('day', AGE(last_assignment_date, first_assignment_date)) AS time_period_days
            FROM assignment_data;
        `;
        const assignmentRateResult = await pool.query(assignmentRateQuery, [userId]);

        // Calculate average assignment rate as a percentage
        const totalAssignedTickets = Number(assignmentRateResult.rows[0].total_assigned_tickets) || 0;
        const timePeriodInDays = Number(assignmentRateResult.rows[0].time_period_days) || 1; // Avoid division by zero

        // Calculate the percentage of tickets assigned per day relative to the total assigned tickets
        const averageAssignmentRatePercentage = ((totalAssignedTickets / timePeriodInDays) / totalAssignedTickets * 100).toFixed(2);

        // Return the response
        res.json({
            total: statsResult.rows[0].total,
            monthly: statsResult.rows[0].monthly,
            averageAssignmentRate: `${averageAssignmentRatePercentage}%`, // Return as a percentage
            priority: {
                low: statsResult.rows[0].low,
                medium: statsResult.rows[0].medium,
                high: statsResult.rows[0].high,
                urgent: statsResult.rows[0].urgent,
            },
        });
    } catch (error) {
        console.error("Error fetching ticket statistics:", error);
        res.status(500).json({ message: "Error fetching ticket statistics", error: error.message });
    }
});

// Route to fetch department-specific ticket stats (admin)
app.get("/tickets/department-stats/:deptId", authenticateUser, async (req, res) => {
    try {
        const { deptId } = req.params;
        const statusQuery = `
            SELECT 
                COUNT(*) FILTER (WHERE status_id = 1) AS pending,
                COUNT(*) FILTER (WHERE status_id = 2) AS on_hold,
                COUNT(*) FILTER (WHERE status_id = 3) AS solved,
                COUNT(*) FILTER (WHERE status_id = 4) AS closed,
                COUNT(*) FILTER (WHERE p.priority_name = 'Low') AS low,
                COUNT(*) FILTER (WHERE p.priority_name = 'Medium') AS medium,
                COUNT(*) FILTER (WHERE p.priority_name = 'High') AS high,
                COUNT(*) FILTER (WHERE p.priority_name = 'Urgent') AS urgent
            FROM tickets t
            LEFT JOIN priority p ON t.priority_id = p.id
            WHERE t.department_id = $1;
        `;
        const statusResult = await pool.query(statusQuery, [deptId]);

        const monthlyQuery = `
            SELECT 
                EXTRACT(MONTH FROM CAST(date_created AS TIMESTAMP)) AS month,
                COUNT(*) FILTER (WHERE status_id = 1) AS pending
            FROM tickets
            WHERE department_id = $1
            GROUP BY EXTRACT(MONTH FROM CAST(date_created AS TIMESTAMP))
            ORDER BY month ASC
            LIMIT 5;
        `;
        const monthlyResult = await pool.query(monthlyQuery, [deptId]);

        const data = {
            pending: Number(statusResult.rows[0].pending) || 0,
            onHold: Number(statusResult.rows[0].on_hold) || 0,
            solved: Number(statusResult.rows[0].solved) || 0,
            closed: Number(statusResult.rows[0].closed) || 0,
            priority: {
                low: Number(statusResult.rows[0].low) || 0,
                medium: Number(statusResult.rows[0].medium) || 0,
                high: Number(statusResult.rows[0].high) || 0,
                urgent: Number(statusResult.rows[0].urgent) || 0,
            },
            monthlyTrends: monthlyResult.rows.map(row => ({
                month: Number(row.month),
                pending: Number(row.pending) || 0,
            })),
        };

        res.json(data);
    } catch (error) {
        console.error(`Error fetching department stats for deptId ${req.params.deptId}:`, error);
        res.status(500).json({ message: "Error fetching department stats", error: error.message });
    }
});

// Fetch All Tickets
app.get("/helpdesk", authenticateUser, async (req, res) => {
    try {
        const query = "SELECT select_all_tickets();";
        const result = await pool.query(query);

        // Parse the JSON string from the function
        const jsonResult = JSON.parse(result.rows[0].select_all_tickets);

        if (!jsonResult.success || !jsonResult.data || jsonResult.data.length === 0) {
            return res.status(404).json({ message: "No helpdesk data found" });
        }

        // Map the tickets data to match AllTickets.jsx expectations
        const tickets = jsonResult.data.map(ticket => ({
            id: ticket.id,
            code: ticket.code || 'N/A',
            complainant_name: ticket.complainant_name || 'Unknown',
            date_created: ticket.date_created || null,
            status: ticket.status_id === 2 ? 'Pending' :
                    ticket.status_id === 3 ? 'On Hold' :
                    ticket.status_id === 4 ? 'Solved' :
                    ticket.status_id === 5 ? 'Closed' : 'Unknown',
            subject: ticket.subject || 'N/A',
            details: ticket.details || 'N/A',
            complainant_number: ticket.complainant_number || 'N/A',
            complainant_office: ticket.complainant_office || 'N/A',
            date_assigned: ticket.date_assigned || null,
            department: ticket.department_id === 1 ? 'Hardware' :
                        ticket.department_id === 2 ? 'Networking' :
                        ticket.department_id === 3 ? 'Software' :
                        ticket.department_id === 4 ? 'IT Support' : 'Unknown',
        }));

        res.json(tickets);
    } catch (error) {
        console.error("Error fetching helpdesk data:", error);
        res.status(500).json({ message: "Error fetching helpdesk data" });
    }
});

app.get("/tickets/monthly", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;

        // Query with corrected departments table join using dept_name
        const query = `
            SELECT 
                t.id,
                t.code,
                t.complainant_name,
                t.date_created,
                t.status_id,
                s.status_name,
                t.subject,
                t.details,
                t.complainant_number,
                t.complainant_office,
                t.date_assigned,
                t.department_id,
                d.dept_name
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            LEFT JOIN departments d ON t.department_id = d.id
            WHERE (t.assigned_userid = $1 OR t.open_id = $1)
            AND DATE_PART('month', t.date_created::timestamp) = DATE_PART('month', CURRENT_DATE)
            AND DATE_PART('year', t.date_created::timestamp) = DATE_PART('year', CURRENT_DATE)
            ORDER BY t.date_created DESC;
        `;
        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No tickets found for this month" });
        }

        // Map the tickets data to a frontend-friendly format
        const tickets = result.rows.map(ticket => ({
            id: ticket.id,
            code: ticket.code || 'N/A',
            complainant_name: ticket.complainant_name || 'Unknown',
            date_created: ticket.date_created || null,
            status: ticket.status_name || 
                    (ticket.status_id === 2 ? 'Pending' :
                     ticket.status_id === 3 ? 'On Hold' :
                     ticket.status_id === 4 ? 'Solved' :
                     ticket.status_id === 5 ? 'Closed' : 'Unknown'),
            subject: ticket.subject || 'N/A',
            details: ticket.details || 'N/A',
            complainant_number: ticket.complainant_number || 'N/A',
            complainant_office: ticket.complainant_office || 'N/A',
            date_assigned: ticket.date_assigned || null,
            department: ticket.dept_name || 
                        (ticket.department_id === 1 ? 'Hardware' :
                         ticket.department_id === 2 ? 'Networking' :
                         ticket.department_id === 3 ? 'Software' :
                         ticket.department_id === 4 ? 'IT Support' : 'Unknown'),
        }));

        res.json(tickets);
    } catch (error) {
        console.error("Error fetching monthly tickets:", error);
        res.status(500).json({ message: "Error fetching monthly tickets", error: error.message });
    }
});

// Route to fetch status-specific ticket details for the user
app.get("/tickets/status-details/:statusId", authenticateUser, async (req, res) => {
    try {
        const { statusId } = req.params;
        const userId = req.userId;

        const ticketsQuery = `
            SELECT 
                t.id,
                t.code,
                t.subject,
                t.status_id,
                s.status_name AS status
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.status_id = $1 AND (t.assigned_userid = $2 OR t.open_id = $2)
            ORDER BY t.date_created DESC;
        `;
        const ticketsResult = await pool.query(ticketsQuery, [statusId, userId]);

        const priorityQuery = `
            SELECT 
                p.priority_name AS priority,
                COUNT(t.id) AS count
            FROM tickets t
            LEFT JOIN priority p ON t.priority_id = p.id
            WHERE t.status_id = $1 AND (t.assigned_userid = $2 OR t.open_id = $2)
            GROUP BY p.priority_name;
        `;
        const priorityResult = await pool.query(priorityQuery, [statusId, userId]);

        const priorityData = priorityResult.rows.reduce((acc, row) => {
            acc[row.priority.toLowerCase()] = Number(row.count) || 0;
            return acc;
        }, { low: 0, medium: 0, high: 0, urgent: 0 });

        res.json({
            tickets: ticketsResult.rows,
            priority: priorityData,
        });
    } catch (error) {
        console.error(`Error fetching status details for statusId ${req.params.statusId}:`, error);
        res.status(500).json({ message: "Error fetching status details", error: error.message });
    }
});

// Status assignment user section
app.put('/tickets/:code/status', authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        const updatingUserId = req.userId;
        const ticketCode = req.params.code;
        const { status } = req.body;
        if (!status || typeof status !== 'string' || status.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Status is required and must be a non-empty string',
                details: {
                    received: status,
                    type: typeof status
                }
            });
        }
        await client.query('BEGIN');
        const statusQuery = await client.query(
            `SELECT id, status_name 
             FROM status 
             WHERE LOWER(status_name) = LOWER($1) 
             AND LOWER(status_name) IN ('on hold', 'solved')`,
            [status.trim()]
        );
        if (statusQuery.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid status value. Must be either "On Hold" or "Solved"',
                details: {
                    receivedStatus: status,
                    availableStatuses: ['On Hold', 'Solved'],
                    suggestion: 'Status must match exactly (case-insensitive)'
                }
            });
        }
        const statusId = statusQuery.rows[0].id;
        const statusName = statusQuery.rows[0].status_name;
        const updateTicketQuery = await client.query(
            `UPDATE tickets
             SET status_id = $1
             WHERE code = $2
             RETURNING id, code, status_id, open_id, assigned_userid`,
            [statusId, ticketCode]
        );
        if (updateTicketQuery.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Ticket not found',
                details: {
                    ticketCode: ticketCode
                }
            });
        }
        const noteDetails = {
            note: statusName.toLowerCase() === 'on hold' ? 'paused' : 'completed',
            user_id: updatingUserId,
            note_date: new Date().toISOString()
        };
        await client.query(
            `INSERT INTO note(ticket_id, note, user_id, date_created)
             VALUES ($1, $2, $3, $4)`,
            [updateTicketQuery.rows[0].id, noteDetails.note, noteDetails.user_id, noteDetails.note_date]
        );
        await client.query('COMMIT');
        // Notify creator and assigned user
        const { open_id, assigned_userid } = updateTicketQuery.rows[0];
        const userIds = [];
        if (open_id) userIds.push(open_id);
        if (assigned_userid) userIds.push(assigned_userid);
        if (userIds.length > 0) {
            await notifyUsers(userIds, 'Ticket Status Updated', `Ticket ${ticketCode} status changed to ${statusName}.`, { ticketId: ticketCode });
        }
        res.status(200).json({
            success: true,
            message: `Ticket status updated to ${statusName} successfully`,
            ticket: updateTicketQuery.rows[0],
            newStatus: statusName,
            noteCreated: true
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Ticket Status Update Error:", error);
        res.status(500).json({
            success: false,
            message: "Error updating ticket status",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    } finally {
        client.release();
    }
});

// Status Assignment admin
app.put('/tickets/:code/status-admin', authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        const updatingUserId = req.userId;
        const ticketCode = req.params.code;
        const { status } = req.body;
        if (!status || typeof status !== 'string' || status.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Status is required and must be a non-empty string',
                details: {
                    received: status,
                    type: typeof status
                }
            });
        }
        await client.query('BEGIN');
        const statusQuery = await client.query(
            `SELECT id, status_name 
             FROM status 
             WHERE LOWER(status_name) = LOWER($1) 
             AND LOWER(status_name) IN ('on hold', 'solved', 'open', 'pending', 'closed')`,
            [status.trim()]
        );
        if (statusQuery.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid status value. Must be one of: "On Hold", "Solved", "Open", "Pending", or "Closed"',
                details: {
                    receivedStatus: status,
                    availableStatuses: ['On Hold', 'Solved', 'Open', 'Pending', 'Closed'],
                    suggestion: 'Status must match exactly (case-insensitive)'
                }
            });
        }
        const statusId = statusQuery.rows[0].id;
        const statusName = statusQuery.rows[0].status_name;
        const updateTicketQuery = await client.query(
            `UPDATE tickets
             SET status_id = $1
             WHERE code = $2
             RETURNING id, code, status_id, open_id, assigned_userid`,
            [statusId, ticketCode]
        );
        if (updateTicketQuery.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Ticket not found',
                details: {
                    ticketCode: ticketCode
                }
            });
        }
        const noteDetails = {
            note: `Status changed to ${statusName} by admin`,
            user_id: updatingUserId,
            note_date: new Date().toISOString()
        };
        await client.query(
            `INSERT INTO note(ticket_id, note, user_id, date_created)
             VALUES ($1, $2, $3, $4)`,
            [updateTicketQuery.rows[0].id, noteDetails.note, noteDetails.user_id, noteDetails.note_date]
        );
        await client.query('COMMIT');
        // Notify creator and assigned user
        const { open_id, assigned_userid } = updateTicketQuery.rows[0];
        const userIds = [];
        if (open_id) userIds.push(open_id);
        if (assigned_userid) userIds.push(assigned_userid);
        if (userIds.length > 0) {
            await notifyUsers(userIds, 'Ticket Status Updated', `Ticket ${ticketCode} status changed to ${statusName}.`, { ticketId: ticketCode });
        }
        res.status(200).json({
            success: true,
            message: `Ticket status updated to ${statusName} successfully`,
            ticket: updateTicketQuery.rows[0],
            newStatus: statusName,
            noteCreated: true,
            updatedBy: 'admin'
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Admin Ticket Status Update Error:", {
            error: error.message,
            stack: error.stack,
            params: req.params,
            body: req.body,
            timestamp: new Date().toISOString()
        });
        res.status(500).json({
            success: false,
            message: "Error updating ticket status",
            error: process.env.NODE_ENV === 'development' ? {
                message: error.message,
                stack: error.stack
            } : undefined
        });
    } finally {
        client.release();
    }
});

//Fetch All Assigned Tickets
app.get("/tickets/assigned-admin", authenticateUser, async (req, res) => {
    try {
        console.log("Entering /tickets/assigned-admin route", { 
            userId: req.userId, 
            userRole: req.userRole, // Add if available
            timestamp: new Date().toISOString() 
        });
        

        const query = `
            SELECT
    t.id,
    t.code,
    t.complainant_name,
    t.date_created,
    t.date_assigned,
    t.details,
    t.status_id,
    s.status_name AS status,
    t.assigned_userid
FROM tickets t
LEFT JOIN status s ON t.status_id = s.id
WHERE t.assigned_userid IS NOT NULL
ORDER BY t.date_created DESC;
        `;
        
        console.log("Executing admin assigned tickets query");
        const result = await pool.query(query);
        
        console.log("Query completed", { 
            rowCount: result.rowCount,
            sampleData: result.rows.length > 0 ? result.rows[0] : null 
        });

        if (result.rows.length === 0) {
            console.log("No assigned tickets found in system");
            return res.status(404).json({ message: "No tickets assigned to any user." });
        }

        res.json(result.rows);
    } catch (error) {
        console.error("Error in /tickets/assigned-admin", {
            error: error.message,
            stack: error.stack,
            query: error.query // If available
        });
        res.status(500).json({ 
            message: "Error fetching assigned tickets",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Route to assign a ticket to a user
app.post("/tickets/assign", authenticateUser, async (req, res) => {
    try {
        const assigningUserId = req.userId;
        const {
            code,
            priority_id,
            assigned_userid,
            date_assigned,
            department_id,
            status_id
        } = req.body;
        if (!code || !priority_id || !assigned_userid || !department_id) {
            return res.status(400).json({ message: "Missing required fields: code, priority_id, assigned_userid, department_id" });
        }
        const ticketDetails = {
            code,
            priority_id,
            assigned_userid,
            date_assigned: date_assigned || new Date().toISOString().split('T')[0],
            department_id,
            status_id: status_id || 1,
            last_updated_by: assigningUserId,
        };
        const query = `
            SELECT re_assign_ticket($1::text) AS result;
        `;
        const result = await pool.query(query, [JSON.stringify(ticketDetails)]);
        const assignmentResult = result.rows[0].result;
        if (assignmentResult === true) {
            // Notify assigned user
            await notifyUsers([assigned_userid], 'Ticket Assigned', `You have been assigned to ticket ${code}.`, { ticketId: code });
            res.status(200).json({
                message: "Ticket assigned successfully",
                ticket: { ...ticketDetails }
            });
        } else {
            return res.status(500).json({ message: "Failed to assign ticket" });
        }
    } catch (error) {
        console.error("Error assigning ticket:", error);
        res.status(500).json({ 
            message: "Error assigning ticket", 
            error: error.message 
        });
    }
});

// Route to fetch all users with their departments and regions for selection
app.get("/users/departments", authenticateUser, async (req, res) => {
    try {
        const query = `
            SELECT select_all_users();
        `;
        const result = await pool.query(query);

        // Parse the JSON result from the function
        const jsonResult = JSON.parse(result.rows[0].select_all_users);

        if (!jsonResult.success || !jsonResult.data || jsonResult.data.length === 0) {
            return res.status(404).json({ message: "No users found" });
        }

        // Extract user data
        const users = jsonResult.data;

        // Group users by department for front-end rendering
        const usersByDepartment = users.reduce((acc, user) => {
            const deptName = user.department || "Unassigned";
            if (!acc[deptName]) {
                acc[deptName] = [];
            }

            const userWithDepartmentId = {
                ...user,
                department_id: user.department_id || null,
            };

            acc[deptName].push(userWithDepartmentId);
            return acc;
        }, {});

        res.status(200).json({
            message: "Users retrieved successfully",
            users: usersByDepartment
        });
    } catch (error) {
        console.error("Error fetching users and departments:", error);
        res.status(500).json({ 
            message: "Error fetching users and departments", 
            error: error.message 
        });
    }
});

// Send generic email
app.post("/get-email", authenticateUser, async (req, res) => {
    const { to, subject, html } = req.body;
    const userId = req.userId;

    if (!to || !subject || !html) {
        return res.status(400).json({ message: "Missing required fields: to, subject, html" });
    }

    try {
        const userQuery = "SELECT email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const response = await resendClient.emails.send({
            from: "onboarding@resend.dev",
            to,
            subject,
            html
        });
        res.status(200).json({ message: "Email sent successfully", response });
    } catch (error) {
        console.error("Error sending email:", error);
        res.status(500).json({ message: "Failed to send email", error: error.message });
    }
});

// Verify current phone number
app.post("/verify-current-phone", authenticateUser, async (req, res) => {
    const { currentPhone } = req.body;
    const userId = req.userId;

    if (!currentPhone || !/^\+?\d{10,15}$/.test(currentPhone)) {
        console.log('Invalid phone number format:', { currentPhone });
        return res.status(400).json({ message: "Invalid phone number format" });
    }

    try {
        const userQuery = "SELECT phone, email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            console.log('User not found:', { userId });
            return res.status(404).json({ message: "User not found" });
        }

        const { phone, email } = userResult.rows[0];
        console.log('Phone numbers comparison:', {
            databasePhone: phone,
            inputPhone: currentPhone
        });

        if (phone !== currentPhone) {
            console.log('Phone number mismatch:', { databasePhone: phone, inputPhone: currentPhone });
            return res.status(400).json({ message: "Current phone number does not match" });
        }

        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "phone_change_verify" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "phone_change_verify",
            value: currentPhone
        });

        await sendPasswordVerificationEmail(email, shortToken, "Phone Verification");

        res.status(200).json({ message: "Verification token sent to your email" });
    } catch (error) {
        console.error("Error verifying current phone:", {
            error: error.message,
            currentPhone,
            userId
        });
        res.status(500).json({ message: "Error verifying current phone", error: error.message });
    }
});



// Verify OTP for phone change verification
app.post("/verify-phone-otp", authenticateUser, async (req, res) => {
    const { token } = req.body;
    const userId = req.userId;

    if (!token || !/^[a-zA-Z0-9]{6}$/.test(token)) {
        console.log('Invalid token format:', { token });
        return res.status(400).json({ message: "Invalid token format" });
    }

    try {
        const tokenData = verificationTokens.get(token.toUpperCase()); // Case-insensitive
        if (!tokenData || tokenData.type !== "phone_change_verify") {
            console.log('Token not found or invalid:', { token });
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        if (decoded.userId !== userId || decoded.type !== "phone_change_verify") {
            console.log('Invalid token for user:', { userId, token });
            return res.status(403).json({ message: "Invalid token" });
        }

        verificationTokens.delete(token.toUpperCase()); // Clear token
        console.log('Phone verification OTP validated:', { token, userId });
        res.status(200).json({ message: "Phone verification OTP validated successfully" });
    } catch (error) {
        console.error("Error verifying phone OTP:", { error: error.message, token, userId });
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token.toUpperCase());
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying phone OTP", error: error.message });
    }
});


app.post("/change-email", authenticateUser, async (req, res) => {
    const { currentEmail } = req.body;
    const userId = req.userId;

    if (!currentEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(currentEmail)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const userQuery = "SELECT email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const { email } = userResult.rows[0];
        if (email !== currentEmail) {
            return res.status(400).json({ message: "Current email does not match" });
        }

        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "email_change_verify" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "email_change_verify",
            value: currentEmail
        });

        await sendEmailVerificationEmail(email, shortToken, "Email Verification");

        res.status(200).json({ message: "Verification token sent to your email" });
    } catch (error) {
        console.error("Error verifying current email:", error);
        res.status(500).json({ message: "Error verifying current email", error: error.message });
    }
});




// Initiate phone number change
app.post("/change-phone", authenticateUser, async (req, res) => {
    const { newPhone, newPhoneNumber } = req.body;
    const phoneToChange = newPhone || newPhoneNumber;
    const userId = req.userId;
     
    console.log('Received new phone number:', { phoneToChange, userId });


    if (!phoneToChange || !/^(233|\+?)\d{10,15}$/.test(phoneToChange)) {
        console.log('Invalid phone number format:', { phoneToChange });
        return res.status(400).json({ message: "Invalid phone number format" });
    }

    try {
        const userQuery = "SELECT email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            console.log('User not found:', { userId });
            return res.status(404).json({ message: "User not found" });
        }
        const userEmail = userResult.rows[0].email;

        const shortToken = generateShortToken();
        const jwtPayload = { userId, newPhone, type: "phone_change" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken.toUpperCase(), {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "phone_change",
            value: newPhone
        });

        await sendPasswordVerificationEmail(userEmail, shortToken, "Phone Change");

        console.log('Phone change OTP sent:', { shortToken, userEmail });
        res.status(200).json({ message: "Verification token sent to your email for phone change" });
    } catch (error) {
        console.error("Error initiating phone change:", { error: error.message, newPhone, userId });
        res.status(500).json({ message: "Error initiating phone change", error: error.message });
    }
});



// Verify OTP for phone number change
app.post("/verify-phone-change-otp", authenticateUser, async (req, res) => {
    const { token } = req.body;
    const userId = req.userId;

    if (!token || token.length !== 6) {
        return res.status(400).json({ message: "Invalid token format" });
    }

    try {
        const tokenData = verificationTokens.get(token);
        if (!tokenData || tokenData.type !== "phone_change") {
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        if (decoded.userId !== userId || decoded.type !== "phone_change") {
            return res.status(403).json({ message: "Invalid token" });
        }

        const client = await pool.connect();
        try {
            await client.query("BEGIN");
            await client.query("UPDATE users SET phone = $1 WHERE id = $2", [decoded.newPhone, userId]);
            await client.query("COMMIT");
            verificationTokens.delete(token);
            res.status(200).json({ message: "Phone number updated successfully" });
        } catch (error) {
            await client.query("ROLLBACK");
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error("Error verifying phone change OTP:", error);
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token);
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying phone change OTP", error: error.message });
    }
});

// Verify current password
app.post("/verify-current-password", authenticateUser, async (req, res) => {
    const { currentPassword } = req.body;
    const userId = req.userId;

    if (!currentPassword || currentPassword.length < 8) {
        return res.status(400).json({ message: "Invalid password format" });
    }

    try {
        const userQuery = "SELECT hashed_pass, email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const { hashed_pass, email } = userResult.rows[0];
        const hashedCurrentPassword = hashPassword(currentPassword);
        if (hashed_pass !== hashedCurrentPassword) {
            return res.status(400).json({ message: "Current password does not match" });
        }

        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "password_change_verify" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "password_change_verify"
        });

        await sendPasswordVerificationEmail(email, shortToken, "Password Verification");

        res.status(200).json({ message: "Verification token sent to your email" });
    } catch (error) {
        console.error("Error verifying current password:", error);
        res.status(500).json({ message: "Error verifying current password", error: error.message });
    }
});

// Verify OTP for password change verification
app.post("/verify-password-otp", authenticateUser, async (req, res) => {
    const { token } = req.body;
    const userId = req.userId;

    if (!token || token.length !== 6) {
        return res.status(400).json({ message: "Invalid token format" });
    }

    try {
        const tokenData = verificationTokens.get(token);
        if (!tokenData || tokenData.type !== "password_change_verify") {
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        if (decoded.userId !== userId || decoded.type !== "password_change_verify") {
            return res.status(403).json({ message: "Invalid token" });
        }

        verificationTokens.delete(token); // Clear token
        res.status(200).json({ message: "Password verification OTP validated successfully" });
    } catch (error) {
        console.error("Error verifying password OTP:", error);
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token);
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying password OTP", error: error.message });
    }
});

// Initiate password change
app.post("/initiate-password-change", authenticateUser, async (req, res) => {
    const userId = req.userId;

    try {
        const userQuery = "SELECT email FROM users WHERE id = $1";
        const userResult = await pool.query(userQuery, [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        const userEmail = userResult.rows[0].email;

        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "password_change" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "password_change"
        });

        await sendPasswordVerificationEmail(userEmail, shortToken, "Password Change");

        res.status(200).json({ message: "Verification token sent to your email for password change" });
    } catch (error) {
        console.error("Error initiating password change:", error);
        res.status(500).json({ message: "Error initiating password change", error: error.message });
    }
});

// Verify OTP for password change
app.post("/verify-password-change-otp", authenticateUser, async (req, res) => {
    const { token } = req.body;
    const userId = req.userId;

    if (!token || token.length !== 6) {
        return res.status(400).json({ message: "Invalid token format" });
    }

    try {
        const tokenData = verificationTokens.get(token);
        if (!tokenData || tokenData.type !== "password_change") {
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        if (decoded.userId !== userId || decoded.type !== "password_change") {
            return res.status(403).json({ message: "Invalid token" });
        }

        verificationTokens.delete(token); // Clear token
        res.status(200).json({ message: "Password change OTP validated successfully" });
    } catch (error) {
        console.error("Error verifying password change OTP:", error);
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token);
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying password change OTP", error: error.message });
    }
});

// Change password
app.post("/user/change-password", authenticateUser, async (req, res) => {
    const { newPassword, confirmPassword } = req.body;
    const userId = req.userId;

    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters" });
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const hashedPassword = hashPassword(newPassword);
            await client.query("UPDATE users SET hashed_pass = $1 WHERE id = $2", [hashedPassword, userId]);

            await client.query("COMMIT");
            res.status(200).json({ message: "Password updated successfully" });
        } catch (error) {
            await client.query("ROLLBACK");
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error("Error changing password:", error);
        res.status(500).json({ message: "Error changing password", error: error.message });
    }
});

// Verify email for password reset
app.post("/verify-email", async (req, res) => {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const userQuery = "SELECT id FROM users WHERE email = $1";
        const userResult = await pool.query(userQuery, [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const userId = userResult.rows[0].id;
        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "password_reset_verify" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "password_reset_verify"
        });

        await sendEmailVerificationEmail(email, shortToken, "Password Reset Verification");

        res.status(200).json({ message: "Verification token sent to your email" });
    } catch (error) {
        console.error("Error verifying email:", error);
        res.status(500).json({ message: "Error verifying email", error: error.message });
    }
});

// Verify OTP for password reset verification
app.post("/verify-password-reset-otp", async (req, res) => {
    const { token, email } = req.body;

    if (!token || token.length !== 6) {
        return res.status(400).json({ message: "Invalid token format" });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const tokenData = verificationTokens.get(token);
        if (!tokenData || tokenData.type !== "password_reset_verify") {
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        const userQuery = "SELECT id FROM users WHERE email = $1";
        const userResult = await pool.query(userQuery, [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const userId = userResult.rows[0].id;
        if (decoded.userId !== userId || decoded.type !== "password_reset_verify") {
            return res.status(403).json({ message: "Invalid token" });
        }

        verificationTokens.delete(token); // Clear token
        res.status(200).json({ message: "Password reset verification OTP validated successfully" });
    } catch (error) {
        console.error("Error verifying password reset OTP:", error);
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token);
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying password reset OTP", error: error.message });
    }
});

// Initiate password reset
app.post("/initiate-password-reset", async (req, res) => {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const userQuery = "SELECT id FROM users WHERE email = $1";
        const userResult = await pool.query(userQuery, [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const userId = userResult.rows[0].id;
        const shortToken = generateShortToken();
        const jwtPayload = { userId, type: "password_reset" };
        const jwtToken = sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: "10m" });

        verificationTokens.set(shortToken, {
            jwt: jwtToken,
            expiresAt: Date.now() + 10 * 60 * 1000,
            type: "password_reset"
        });

        await sendPasswordVerificationEmail(email, shortToken, "Password Reset");

        res.status(200).json({ message: "Verification token sent to your email for password reset" });
    } catch (error) {
        console.error("Error initiating password reset:", error);
        res.status(500).json({ message: "Error initiating password reset", error: error.message });
    }
});

// Verify OTP for password reset
app.post("/verify-password-reset-change-otp", async (req, res) => {
    const { token, email } = req.body;

    if (!token || token.length !== 6) {
        return res.status(400).json({ message: "Invalid token format" });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const tokenData = verificationTokens.get(token);
        if (!tokenData || tokenData.type !== "password_reset") {
            return res.status(404).json({ message: "Token not found or invalid" });
        }

        const decoded = verify(tokenData.jwt, process.env.JWT_SECRET);
        const userQuery = "SELECT id FROM users WHERE email = $1";
        const userResult = await pool.query(userQuery, [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const userId = userResult.rows[0].id;
        if (decoded.userId !== userId || decoded.type !== "password_reset") {
            return res.status(403).json({ message: "Invalid token" });
        }

        verificationTokens.delete(token); // Clear token
        res.status(200).json({ message: "Password reset OTP validated successfully" });
    } catch (error) {
        console.error("Error verifying password reset change OTP:", error);
        if (error.name === "TokenExpiredError") {
            verificationTokens.delete(token);
            return res.status(403).json({ message: "Token has expired" });
        }
        res.status(500).json({ message: "Error verifying password reset change OTP", error: error.message });
    }
});

// Reset password
app.post("/reset-password", async (req, res) => {
    const { newPassword, confirmPassword, email } = req.body;

    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters" });
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    try {
        const userQuery = "SELECT id FROM users WHERE email = $1";
        const userResult = await pool.query(userQuery, [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const userId = userResult.rows[0].id;
        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const hashedPassword = hashPassword(newPassword);
            await client.query("UPDATE users SET hashed_pass = $1 WHERE id = $2", [hashedPassword, userId]);

            await client.query("COMMIT");
            res.status(200).json({ message: "Password reset successfully" });
        } catch (error) {
            await client.query("ROLLBACK");
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).json({ message: "Error resetting password", error: error.message });
    }
});


// Get all checklist records
app.post('/dc/daily/get-records', authenticateUser, async (req, res) => {
  try {
    const { action, date } = req.body;
    
    if (action !== 'get-records') {
      return res.status(400).json({ error: 'Invalid action' });
    }

    // Validate date format (YYYY-MM-DD) if provided
    if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    // Call the PostgreSQL function
    const result = await pool.query('SELECT get_checklist_records()');
    const functionResult = result.rows[0].get_checklist_records;

    // Extract records from function result
    let records = functionResult.data || [];

    // Apply date filtering if date parameter is provided
    // Since the function doesn't support date filtering, we filter in JavaScript
    if (date) {
      records = records.filter(record => {
        const recordDate = new Date(record.createdAt);
        const filterDate = new Date(date);
        return recordDate.toDateString() === filterDate.toDateString();
      });
    }

    // Transform the data to match your expected format
    const transformedRecords = records.map(record => ({
      id: record.id,
      userId: record.userId,
      locationId: record.locationId,
      locationName: null, // Function doesn't return location name
      createdAt: record.createdAt,
      username: record.username,
      status: record.data.status,
      data: {
        itemId: record.data.itemId,
        status: record.data.status,
        categoryId: null, // Function doesn't return categoryId
        categoryName: record.data.categoryName,
        itemDescription: record.data.itemDescription,
        comment: record.data.comment // Additional field from function
      }
    }));

    console.log(`Fetched ${transformedRecords.length} records for date: ${date || 'all dates'}`);
    res.json({ 
      records: transformedRecords,
      totalCount: functionResult.count // Additional info from function
    });

  } catch (error) {
    console.error('Error fetching records:', error.message);
    res.status(500).json({ 
      error: 'Internal server error', 
      details: error.message,
      stack: error.stack 
    });
  }
});


// Get all locations
app.post('/dc/daily/get-locations', authenticateUser, async (req, res) => {
  try {
    if (req.body.action !== 'get-locations') {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const result = await pool.query('SELECT * FROM get_locations()');
    res.json({ locations: result.rows });
  } catch (error) {
    console.error('Error fetching locations:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all categories
app.post('/dc/daily/get-categories', authenticateUser, async (req, res) => {
  try {
    if (req.body.action !== 'get-categories') {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const result = await pool.query('SELECT * FROM get_categories()');
    res.json({ categories: result.rows });
  } catch (error) {
    console.error('Error fetching categories:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all checklist items
app.post('/dc/daily/get-checklist-items', authenticateUser, async (req, res) => {
  try {
    if (req.body.action !== 'get-checklist-items') {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const result = await pool.query('SELECT * FROM get_checklist_items()');
    res.json({ items: result.rows });
  } catch (error) {
    console.error('Error fetching checklist items:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//Save checklist
app.post('/dc/daily/save-checklist', authenticateUser, async (req, res) => {
    const { action, data } = req.body;
    
    console.log('Received save-checklist request:', { 
      action, 
      data: { 
        ...data, 
        responses: data?.responses?.length 
      } 
    });
    
    // Validate request
    if (action !== 'save-checklist') {
      return res.status(400).json({ error: 'Invalid action specified' });
    }
    
    if (!data) {
      return res.status(400).json({ error: 'Missing data in request' });
    }
    
    const { responses, location_id, category_id, inspector } = data;
    const userId = req.user?.userId || data.user_id;
    
    if (!responses || !Array.isArray(responses)) {
      return res.status(400).json({ error: 'Invalid responses format' });
    }
    
    if (!location_id) {
      return res.status(400).json({ error: 'Missing location_id' });
    }
  
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      console.log('Calling save_checklist function with:', {
        userId, 
        location_id,
        category_id,
        responsesCount: responses.length
      });
      
      // Check if this category has already been submitted today (updated query)
      if (category_id) {
        const existingSubmission = await client.query(
          `SELECT 1 FROM checklist_records cr
           JOIN checklist_items ci ON cr.item_id = ci.item_id
           WHERE cr.location_id = $1 
           AND cr.user_id = $2
           AND ci.category_id = $3
           AND cr.inspection_date = CURRENT_DATE
           LIMIT 1`,
          [location_id, userId, category_id]
        );
        
        if (existingSubmission.rows.length > 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ 
            error: 'This category has already been submitted for today',
            category_id,
            location_id
          });
        }
      }
      
      const result = await client.query(
        'SELECT save_checklist($1, $2, $3, $4, $5) as result',
        [userId, location_id, inspector, JSON.stringify(responses), category_id || null]
      );
      
      const functionResult = result.rows[0].result;
      console.log('Function returned:', functionResult);
      
      if (functionResult.success) {
        // Check if all categories are completed for this location today (updated query)
        const categoriesResult = await client.query('SELECT COUNT(*) FROM categories');
        const totalCategories = parseInt(categoriesResult.rows[0].count, 10);
        
        const completedCategoriesResult = await client.query(
          `SELECT COUNT(DISTINCT ci.category_id) 
           FROM checklist_records cr
           JOIN checklist_items ci ON cr.item_id = ci.item_id
           WHERE cr.location_id = $1 
           AND cr.user_id = $2
           AND cr.inspection_date = CURRENT_DATE`,
          [location_id, userId]
        );
        
        const completedCategories = parseInt(completedCategoriesResult.rows[0].count, 10);
        
        // If all categories completed, send notification
        if (completedCategories >= totalCategories) {
          const locationResult = await client.query(
            'SELECT location_name FROM locations WHERE location_id = $1',
            [location_id]
          );
          
          const locationName = locationResult.rows[0]?.name || `Location ${location_id}`;
          
          const tokenResult = await client.query(
            'SELECT device_token FROM device_tokens WHERE user_id = $1',
            [userId]
          );
          
          if (tokenResult.rows.length > 0) {
            const deviceToken = tokenResult.rows[0].device_token;
            
            await sendPushNotification(
              [deviceToken],
              'Checklist Completed',
              `All daily checks completed for ${locationName}!`,
              { 
                locationId: location_id,
                locationName: locationName
              }
            );
            
            await client.query(
              'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
              [userId, `Completed all daily checks for ${locationName}`]
            );
            
            console.log(`Notification sent for completed checks at ${locationName}`);
          }
        }
        
        await client.query('COMMIT');
        return res.json({
          ...functionResult,
          completedCategories,
          totalCategories,
          isLocationComplete: completedCategories >= totalCategories
        });
      } else {
        await client.query('ROLLBACK');
        return res.status(400).json(functionResult);
      }
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Transaction error:', error);
      return res.status(500).json({ 
        error: 'Database error',
        message: error.message 
      });
    } finally {
      client.release();
    }
  });

// Get user-specific records
app.post('/dc/daily/get-user-records', authenticateUser, async (req, res) => {
  try {
    const { action, data } = req.body;
    if (action !== 'get-user-records') {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const userId = req.user?.userId || data?.user_id;
    if (!userId) {
      return res.status(400).json({ error: 'User ID is missing' });
    }

    const result = await pool.query(`SELECT * FROM get_user_records($1)`, [userId]);

    const records = result.rows.map(record => ({
      id: record.id,
      userId: record.user_id,
      locationId: record.location_id,
      locationName: record.location_name,
      createdAt: record.inspection_date,
      username: record.username,
      data: record.data
    }));

    res.json({ records });
  } catch (error) {
    console.error('Error in get-user-records:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Middleware to set request timeout (10 seconds)
app.use((req, res, next) => {
    res.setTimeout(10000, () => {
        res.status(408).json({ message: "Request timed out" });
    });
    next();
});

// Global error handler for uncaught exceptions
app.use((err, req, res, next) => {
    console.error("Server Error:", err);
    res.status(500).json({ message: "Internal Server Error", error: err.message });
});

// Start server on specified port (default 3001)
const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
