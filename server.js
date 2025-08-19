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
// Store to track last processed assignment timestamps
let lastProcessedAssignment = new Date();
 
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

// Function to check for new ticket assignments from web version
const checkForNewAssignments = async () => {
    const client = await pool.connect();
    try {
        console.log('Checking for new ticket assignments...');
        
        // Check for tickets assigned to specific users that haven't been notified
        const userAssignmentsQuery = `
            SELECT 
                t.id,
                t.code,
                t.assigned_userid,
                t.date_assigned,
                t.subject,
                t.open_id,
                u.first_name,
                u.surname,
                u.email
            FROM tickets t
            LEFT JOIN users u ON t.assigned_userid = u.id
            WHERE t.assigned_userid IS NOT NULL 
            AND t.assigned_userid > 0
            AND (
                t.date_assigned::timestamp > $1
                OR (
                    t.date_assigned::timestamp = $1::timestamp 
                    AND t.id NOT IN (
                        SELECT DISTINCT CAST(SUBSTRING(message, 'ticket ([A-Z0-9]+)') AS VARCHAR)
                        FROM notifications 
                        WHERE message LIKE '%assigned to ticket%'
                        AND created_at > $1
                    )
                )
            )
            AND NOT EXISTS (
                SELECT 1 FROM notifications n 
                WHERE n.user_id = t.assigned_userid::varchar
                AND n.message LIKE '%assigned to ticket ' || t.code || '%'
                AND n.created_at > $1
            )
            ORDER BY t.date_assigned DESC;
        `;

        const userAssignments = await client.query(userAssignmentsQuery, [lastProcessedAssignment]);
        
        // Check for tickets assigned to departments
        const deptAssignmentsQuery = `
            SELECT DISTINCT
                t.id,
                t.code,
                t.department_id,
                t.date_assigned,
                t.subject,
                t.open_id,
                d.dept_name,
                array_agg(u.id) as user_ids,
                array_agg(u.first_name || ' ' || u.surname) as user_names
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN users u ON u.department_id = t.department_id::varchar AND u.status = '1'
            WHERE t.department_id IS NOT NULL 
            AND t.assigned_userid IS NULL
            AND (
                t.date_assigned::timestamp > $1
                OR t.date_assigned IS NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM notifications n 
                WHERE n.message LIKE '%ticket ' || t.code || '%department%'
                AND n.created_at > $1
            )
            GROUP BY t.id, t.code, t.department_id, t.date_assigned, t.subject, t.open_id, d.dept_name
            ORDER BY t.date_assigned DESC NULLS LAST;
        `;

        const deptAssignments = await client.query(deptAssignmentsQuery, [lastProcessedAssignment]);

        // Process user assignments
        for (const assignment of userAssignments.rows) {
            try {
                console.log(`Processing user assignment: ${assignment.code} to user ${assignment.assigned_userid}`);
                
                const notificationPromises = [];
                const pushNotificationUserIds = [];

                // Notify the assigned user
                if (assignment.assigned_userid) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [assignment.assigned_userid, `You have been assigned to ticket ${assignment.code} via web dashboard`]
                        )
                    );
                    pushNotificationUserIds.push(assignment.assigned_userid);
                }

                // Notify the ticket creator if different from assigned user
                if (assignment.open_id && assignment.open_id !== assignment.assigned_userid) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [assignment.open_id, `Your ticket ${assignment.code} has been assigned to ${assignment.first_name} ${assignment.surname} for resolution`]
                        )
                    );
                    if (!pushNotificationUserIds.includes(assignment.open_id)) {
                        pushNotificationUserIds.push(assignment.open_id);
                    }
                }

                // Execute all notification insertions
                await Promise.all(notificationPromises);

                // Send push notifications
                if (pushNotificationUserIds.length > 0) {
                    await notifyUsers(
                        pushNotificationUserIds, 
                        'Ticket Assignment', 
                        `Ticket ${assignment.code} has been assigned via web dashboard.`, 
                        { ticketId: assignment.code, assignmentType: 'user' }
                    );
                }

                console.log(`Successfully processed user assignment for ticket ${assignment.code}`);
                
            } catch (error) {
                console.error(`Error processing user assignment ${assignment.code}:`, error.message);
            }
        }

        // Process department assignments
        for (const assignment of deptAssignments.rows) {
            try {
                console.log(`Processing department assignment: ${assignment.code} to department ${assignment.dept_name}`);
                
                const userIds = assignment.user_ids.filter(id => id !== null);
                
                if (userIds.length === 0) {
                    console.log(`No active users found in department ${assignment.dept_name} for ticket ${assignment.code}`);
                    continue;
                }

                const notificationPromises = [];
                const pushNotificationUserIds = [];

                // Notify all users in the department
                userIds.forEach(userId => {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [userId, `A ticket ${assignment.code} has been assigned to your department (${assignment.dept_name}) via web dashboard`]
                        )
                    );
                    pushNotificationUserIds.push(userId);
                });

                // Notify the ticket creator if different from department users
                if (assignment.open_id && !userIds.includes(assignment.open_id)) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [assignment.open_id, `Your ticket ${assignment.code} has been assigned to ${assignment.dept_name} department for resolution`]
                        )
                    );
                    if (!pushNotificationUserIds.includes(assignment.open_id)) {
                        pushNotificationUserIds.push(assignment.open_id);
                    }
                }

                // Execute all notification insertions
                await Promise.all(notificationPromises);

                // Send push notifications
                if (pushNotificationUserIds.length > 0) {
                    await notifyUsers(
                        pushNotificationUserIds, 
                        'Department Ticket Assignment', 
                        `Ticket ${assignment.code} assigned to ${assignment.dept_name} department via web dashboard.`, 
                        { ticketId: assignment.code, assignmentType: 'department', department: assignment.dept_name }
                    );
                }

                console.log(`Successfully processed department assignment for ticket ${assignment.code}`);
                
            } catch (error) {
                console.error(`Error processing department assignment ${assignment.code}:`, error.message);
            }
        }

        // Update last processed timestamp
        lastProcessedAssignment = new Date();
        
        if (userAssignments.rowCount > 0 || deptAssignments.rowCount > 0) {
            console.log(`Processed ${userAssignments.rowCount} user assignments and ${deptAssignments.rowCount} department assignments`);
        }

    } catch (error) {
        console.error('Error checking for new assignments:', error.message);
    } finally {
        client.release();
    }
};

// Function to check for ticket status updates from web version
const checkForStatusUpdates = async () => {
    const client = await pool.connect();
    try {
        console.log('Checking for ticket status updates...');
        
        // Check for status changes that haven't been notified
        const statusUpdatesQuery = `
            SELECT 
                t.id,
                t.code,
                t.status_id,
                t.assigned_userid,
                t.open_id,
                s.status_name,
                GREATEST(
                    COALESCE(EXTRACT(EPOCH FROM t.date_created::timestamp), 0),
                    COALESCE(EXTRACT(EPOCH FROM t.date_assigned::timestamp), 0)
                ) as last_modified_epoch
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            WHERE GREATEST(
                COALESCE(t.date_created::timestamp, '1970-01-01'::timestamp),
                COALESCE(t.date_assigned::timestamp, '1970-01-01'::timestamp)
            ) > $1
            AND t.status_id IN (2, 3, 4, 5) -- Pending, On Hold, Solved, Closed
            AND NOT EXISTS (
                SELECT 1 FROM notifications n 
                WHERE (n.user_id = t.assigned_userid::varchar OR n.user_id = t.open_id::varchar)
                AND n.message LIKE '%ticket ' || t.code || '%status%'
                AND n.created_at > $1
            )
            ORDER BY last_modified_epoch DESC;
        `;

        const statusUpdates = await client.query(statusUpdatesQuery, [lastProcessedAssignment]);

        // Process status updates
        for (const update of statusUpdates.rows) {
            try {
                console.log(`Processing status update: ${update.code} to ${update.status_name}`);
                
                const notificationPromises = [];
                const pushNotificationUserIds = [];

                // Notify assigned user
                if (update.assigned_userid) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [update.assigned_userid, `Ticket ${update.code} status has been changed to ${update.status_name} via web dashboard`]
                        )
                    );
                    pushNotificationUserIds.push(update.assigned_userid);
                }

                // Notify ticket creator
                if (update.open_id && update.open_id !== update.assigned_userid) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [update.open_id, `Your ticket ${update.code} status has been changed to ${update.status_name}`]
                        )
                    );
                    if (!pushNotificationUserIds.includes(update.open_id)) {
                        pushNotificationUserIds.push(update.open_id);
                    }
                }

                // Execute all notification insertions
                await Promise.all(notificationPromises);

                // Send push notifications
                if (pushNotificationUserIds.length > 0) {
                    await notifyUsers(
                        pushNotificationUserIds, 
                        'Ticket Status Update', 
                        `Ticket ${update.code} status changed to ${update.status_name}.`, 
                        { ticketId: update.code, status: update.status_name, source: 'web_dashboard' }
                    );
                }

                console.log(`Successfully processed status update for ticket ${update.code}`);
                
            } catch (error) {
                console.error(`Error processing status update ${update.code}:`, error.message);
            }
        }

        if (statusUpdates.rowCount > 0) {
            console.log(`Processed ${statusUpdates.rowCount} status updates`);
        }

    } catch (error) {
        console.error('Error checking for status updates:', error.message);
    } finally {
        client.release();
    }
};

// Start the polling mechanism - check every 30 seconds
const startAssignmentMonitoring = () => {
    console.log('Starting assignment monitoring service...');
    
    // Initial delay to allow server to fully start
    setTimeout(() => {
        // Run immediately on start
        checkForNewAssignments();
        checkForStatusUpdates();
        
        // Then run every 30 seconds
        setInterval(() => {
            checkForNewAssignments();
            checkForStatusUpdates();
        }, 30000); // 30 seconds
        
        console.log('Assignment monitoring service started successfully');
    }, 5000); // 5 second initial delay
};


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


// Add root route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the IT Admin Backend!' });
});


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

// Add this route to manually trigger assignment check (useful for testing)
app.post('/check-assignments', authenticateUser, async (req, res) => {
    try {
        console.log('Manual assignment check triggered by user:', req.userId);
        await checkForNewAssignments();
        await checkForStatusUpdates();
        res.json({ 
            message: 'Assignment check completed successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Manual assignment check failed:', error.message);
        res.status(500).json({ 
            message: 'Assignment check failed', 
            error: error.message 
        });
    }
});

// Add this route to get monitoring status
app.get('/monitoring-status', authenticateUser, (req, res) => {
    res.json({
        status: 'active',
        lastProcessedAssignment: lastProcessedAssignment,
        monitoringInterval: '30 seconds',
        startTime: new Date().toISOString()
    });
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

// Route to fetch tickets assigned to the user's department
app.get("/tickets/department", authenticateUser, async (req, res) => {
    try {
        const userId = req.userId;
        console.log("Fetching department tickets for user:", { userId });

        // Get user's department first
        const userDeptQuery = `
            SELECT department_id, first_name, surname 
            FROM users 
            WHERE id = $1;
        `;
        const userResult = await pool.query(userDeptQuery, [userId]);

        if (userResult.rows.length === 0) {
            console.log("User not found", { userId });
            return res.status(404).json({ message: "User not found." });
        }

        const { department_id, first_name, surname } = userResult.rows[0];
        
        if (!department_id) {
            console.log("User not assigned to any department", { userId });
            return res.status(404).json({ message: "You are not assigned to any department." });
        }

        // Fetch tickets assigned to user's department that are not yet assigned to a specific user
        const ticketsQuery = `
            SELECT 
                t.id,
                t.code,
                t.subject,
                t.details,
                t.date_created,
                t.complainant_name,
                t.status_id,
                t.priority_id,
                t.department_id,
                s.status_name AS status,
                p.priority_name AS priority,
                d.dept_name AS department_name
            FROM tickets t
            LEFT JOIN status s ON t.status_id = s.id
            LEFT JOIN priority p ON t.priority_id = p.id
            LEFT JOIN departments d ON t.department_id = d.id
            WHERE t.department_id = $1 
            AND (t.assigned_userid IS NULL OR t.assigned_userid = 0)
            AND t.status_id NOT IN (4, 5) -- Exclude solved and closed tickets
            ORDER BY 
                CASE 
                    WHEN p.priority_name = 'Urgent' THEN 1
                    WHEN p.priority_name = 'High' THEN 2
                    WHEN p.priority_name = 'Medium' THEN 3
                    WHEN p.priority_name = 'Low' THEN 4
                    ELSE 5
                END ASC,
                t.date_created ASC;
        `;
        
        const ticketsResult = await pool.query(ticketsQuery, [department_id]);
        
        console.log("Department tickets fetched", { 
            userId, 
            departmentId: department_id, 
            ticketCount: ticketsResult.rows.length 
        });

        if (ticketsResult.rows.length === 0) {
            return res.status(200).json({
                message: "No unassigned tickets found for your department.",
                tickets: [],
                departmentId: department_id
            });
        }

        // Format the response data
        const formattedTickets = ticketsResult.rows.map(ticket => ({
            id: ticket.id,
            code: ticket.code,
            subject: ticket.subject || 'No Subject',
            details: ticket.details || 'No Details',
            date_created: ticket.date_created,
            complainant_name: ticket.complainant_name || 'Unknown',
            status: ticket.status || 'Unknown',
            priority: ticket.priority || 'Unknown',
            department_name: ticket.department_name || 'Unknown Department',
            status_id: ticket.status_id,
            priority_id: ticket.priority_id,
            department_id: ticket.department_id
        }));

        res.json({
            tickets: formattedTickets,
            departmentId: department_id,
            userName: `${first_name} ${surname}`,
            totalCount: formattedTickets.length
        });

    } catch (error) {
        console.error("Error fetching department tickets", { 
            userId: req.userId, 
            error: error.message, 
            stack: error.stack 
        });
        res.status(500).json({ 
            message: "Error fetching department tickets",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

// Route to accept a ticket (assign it to the signed-in user)
app.post("/tickets/accept/:ticketCode", authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const userId = req.userId;
        const ticketCode = req.params.ticketCode;
        
        console.log("User attempting to accept ticket", { userId, ticketCode });

        // Validate ticket code
        if (!ticketCode) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                success: false,
                message: "Ticket code is required" 
            });
        }

        // Get user details and department
        const userQuery = `
            SELECT 
                u.id,
                u.first_name,
                u.surname,
                u.department_id,
                d.dept_name
            FROM users u
            LEFT JOIN departments d ON u.department_id = d.id
            WHERE u.id = $1;
        `;
        const userResult = await client.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ 
                success: false,
                message: "User not found" 
            });
        }

        const user = userResult.rows[0];
        const userName = `${user.first_name} ${user.surname}`;

        if (!user.department_id) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                success: false,
                message: "You are not assigned to any department and cannot accept tickets" 
            });
        }

        // Check if ticket exists and get its current status
        const ticketQuery = `
            SELECT 
                t.id,
                t.code,
                t.subject,
                t.department_id,
                t.assigned_userid,
                t.status_id,
                t.open_id,
                d.dept_name,
                s.status_name
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN status s ON t.status_id = s.id
            WHERE t.code = $1;
        `;
        const ticketResult = await client.query(ticketQuery, [ticketCode]);

        if (ticketResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ 
                success: false,
                message: "Ticket not found" 
            });
        }

        const ticket = ticketResult.rows[0];

        // Check if ticket belongs to user's department
        if (ticket.department_id !== user.department_id) {
            await client.query('ROLLBACK');
            return res.status(403).json({ 
                success: false,
                message: `This ticket is assigned to ${ticket.dept_name} department, but you belong to ${user.dept_name} department` 
            });
        }

        // Check if ticket is already assigned to someone
        if (ticket.assigned_userid && ticket.assigned_userid > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                success: false,
                message: "This ticket has already been accepted by another user" 
            });
        }

        // Check if ticket is in a state that can be accepted
        if (ticket.status_id === 4 || ticket.status_id === 5) { // Solved or Closed
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                success: false,
                message: "Cannot accept a ticket that is already solved or closed" 
            });
        }

        // Update ticket to assign it to the user
        const updateQuery = `
            UPDATE tickets 
            SET 
                assigned_userid = $1,
                date_assigned = CURRENT_DATE,
                status_id = CASE 
                    WHEN status_id = 1 THEN 2  -- Change from Open to Pending if it was Open
                    ELSE status_id             -- Keep current status otherwise
                END
            WHERE code = $2
            RETURNING 
                id, code, subject, assigned_userid, status_id, date_assigned;
        `;
        const updateResult = await client.query(updateQuery, [userId, ticketCode]);

        if (updateResult.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(500).json({ 
                success: false,
                message: "Failed to accept ticket" 
            });
        }

        const updatedTicket = updateResult.rows[0];

        // Insert notifications into notifications table
        const notificationPromises = [];
        
        // Notify the user who accepted the ticket
        notificationPromises.push(
            client.query(
                'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                [userId, `Successfully accepted ticket ${ticketCode}`]
            )
        );
        
        // Notify the ticket creator if they exist
        if (ticket.open_id && ticket.open_id !== userId) {
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [ticket.open_id, `Your ticket ${ticketCode} has been accepted by ${userName} and is now being worked on`]
                )
            );
        }
        
        // Execute all notification insertions
        await Promise.all(notificationPromises);
        
        await client.query('COMMIT');

        // Send push notifications
        const pushNotificationUserIds = [];
        if (ticket.open_id && ticket.open_id !== userId) {
            pushNotificationUserIds.push(ticket.open_id);
        }
        
        if (pushNotificationUserIds.length > 0) {
            await notifyUsers(
                pushNotificationUserIds, 
                'Ticket Accepted', 
                `Your ticket ${ticketCode} has been accepted by ${userName}.`, 
                { ticketId: ticketCode }
            );
        }

        console.log("Ticket accepted successfully", {
            ticketCode,
            userId,
            userName,
            assignedDate: updatedTicket.date_assigned
        });

        res.status(200).json({
            success: true,
            message: `Ticket ${ticketCode} accepted successfully`,
            ticket: {
                id: updatedTicket.id,
                code: updatedTicket.code,
                subject: updatedTicket.subject,
                assigned_userid: updatedTicket.assigned_userid,
                assigned_user_name: userName,
                date_assigned: updatedTicket.date_assigned,
                status_id: updatedTicket.status_id
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error accepting ticket:", {
            error: error.message,
            stack: error.stack,
            ticketCode: req.params.ticketCode,
            userId: req.userId
        });
        res.status(500).json({
            success: false,
            message: "Error accepting ticket",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    } finally {
        client.release();
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
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    
    console.log(`[${requestId}] Ticket submission request started`, {
        timestamp: new Date().toISOString(),
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        hasAuth: !!req.headers.authorization
    });

    const { name, division, phoneNumber, office, priority, subject, details, staffId, region } = req.body;
    
    // Log request payload (sanitized)
    console.log(`[${requestId}] Request payload received`, {
        name: name ? '[REDACTED]' : undefined,
        division,
        phoneNumber: phoneNumber ? '[REDACTED]' : undefined,
        office,
        priority,
        subject: subject ? subject.substring(0, 50) + '...' : undefined,
        detailsLength: details ? details.length : 0,
        staffId: staffId ? '[REDACTED]' : undefined,
        region
    });
    
    // Validate required fields
    if (!name || !division || !phoneNumber || !office || !priority || !subject || !details || !region) {
        const missingFields = [];
        if (!name) missingFields.push('name');
        if (!division) missingFields.push('division');
        if (!phoneNumber) missingFields.push('phoneNumber');
        if (!office) missingFields.push('office');
        if (!priority) missingFields.push('priority');
        if (!subject) missingFields.push('subject');
        if (!details) missingFields.push('details');
        if (!region) missingFields.push('region');
        
        console.warn(`[${requestId}] Validation failed - missing required fields`, {
            missingFields,
            duration: Date.now() - startTime
        });
        
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Validate staffId if provided
    if (staffId && typeof staffId !== 'string') {
        console.warn(`[${requestId}] Validation failed - invalid staffId type`, {
            staffIdType: typeof staffId,
            duration: Date.now() - startTime
        });
        return res.status(400).json({ success: false, message: 'Staff ID must be a string' });
    }

    // Validate subject and details length to prevent database issues
    if (subject.length > 255) {
        console.warn(`[${requestId}] Validation failed - subject too long`, {
            subjectLength: subject.length,
            duration: Date.now() - startTime
        });
        return res.status(400).json({ success: false, message: 'Subject must be 255 characters or less' });
    }

    if (details.length > 5000) {
        console.warn(`[${requestId}] Validation failed - details too long`, {
            detailsLength: details.length,
            duration: Date.now() - startTime
        });
        return res.status(400).json({ success: false, message: 'Details must be 5000 characters or less' });
    }

    // Region mapping
    const regionMapping = {
        'Greater Accra': 1,
        'Eastern': 2,
        'Ashanti': 3,
        'Western': 4,
        'Volta': 5,
        'Oti': 6,
        'Western North': 7,
        'Bono': 8,
        'Bono East': 9,
        'Ahafo': 10,
        'Savannah': 11,
        'Northern': 12,
        'North East': 13,
        'Upper East': 14,
        'Upper West': 15,
        'Central': 16,
        'Tema': 17
    };

    const regionId = regionMapping[region];
    
    if (!regionId) {
        console.warn(`[${requestId}] Validation failed - invalid region`, {
            providedRegion: region,
            validRegions: Object.keys(regionMapping),
            duration: Date.now() - startTime
        });
        
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid region specified',
            validRegions: Object.keys(regionMapping)
        });
    }

    // Division mapping with validation
    const divisionMapping = {
        'lvd': 1,
        'pvlmd': 2,
        'lrd': 3,
        'smd': 4,
        'corporate': 5
    };

    const divisionId = divisionMapping[division.toLowerCase()];
    if (!divisionId) {
        console.warn(`[${requestId}] Validation failed - invalid division`, {
            providedDivision: division,
            validDivisions: Object.keys(divisionMapping),
            duration: Date.now() - startTime
        });
        
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid division specified',
            validDivisions: Object.keys(divisionMapping)
        });
    }

    // Priority mapping with validation
    const priorityMapping = {
        'urgent': 1,
        'high': 2,
        'medium': 3,
        'low': 4
    };

    const priorityId = priorityMapping[priority.toLowerCase()];
    if (!priorityId) {
        console.warn(`[${requestId}] Validation failed - invalid priority`, {
            providedPriority: priority,
            validPriorities: Object.keys(priorityMapping),
            duration: Date.now() - startTime
        });
        
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid priority specified',
            validPriorities: Object.keys(priorityMapping)
        });
    }

    console.log(`[${requestId}] Validation passed, attempting database connection`);

    const client = await pool.connect();
    try {
        console.log(`[${requestId}] Database connection established, beginning transaction`);
        await client.query('BEGIN');
        
        let userId = null;
        if (req.headers.authorization) {
            console.log(`[${requestId}] Processing authentication token`);
            try {
                const authHeader = req.headers.authorization;
                if (authHeader.startsWith('Bearer ')) {
                    const token = authHeader.split(' ')[1];
                    const decoded = verify(token, process.env.JWT_SECRET);
                    userId = decoded.userId;
                    console.log(`[${requestId}] Authentication successful`, { userId });
                } else {
                    console.warn(`[${requestId}] Invalid authorization header format`);
                }
            } catch (error) {
                console.warn(`[${requestId}] Authentication attempt failed, proceeding as unauthenticated`, {
                    error: error.message,
                    errorType: error.name
                });
            }
        } else {
            console.log(`[${requestId}] No authentication header provided, proceeding as unauthenticated`);
        }

        // Validate that region and division exist in the database
        console.log(`[${requestId}] Validating region and division in database`);
        const regionValidation = await client.query('SELECT region_code FROM regions WHERE id = $1', [regionId]);
        const divisionValidation = await client.query('SELECT division_code FROM divisions WHERE id = $1', [divisionId]);

        if (regionValidation.rows.length === 0) {
            console.error(`[${requestId}] Region validation failed - region not found in database`, {
                regionId,
                duration: Date.now() - startTime
            });
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid region - region not found in database',
            });
        }

        if (divisionValidation.rows.length === 0) {
            console.error(`[${requestId}] Division validation failed - division not found in database`, {
                divisionId,
                duration: Date.now() - startTime
            });
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Invalid division - division not found in database',
            });
        }

        console.log(`[${requestId}] Database validation successful`, {
            regionCode: regionValidation.rows[0].region_code,
            divisionCode: divisionValidation.rows[0].division_code
        });

        // Generate a more robust PIN
        const pin = Math.floor(1000 + Math.random() * 9000);
        const currentDateTime = new Date().toISOString();

        const ticketDetails = {
            staff_id: staffId || null,
            region_id: regionId,
            division_id: divisionId,
            priority_id: priorityId,
            is_assigned: 0,
            assigned_userid: null,
            date_assigned: 'N/A',
            department_id: null,
            subject: subject.trim(),
            details: details.trim(),
            complainant_name: name.trim(),
            complainant_number: phoneNumber.trim(),
            complainant_office: office.trim(),
            status_id: 1,
            open_id: userId,
            pin: pin,
            created_by: name.trim(),
            date_created: currentDateTime,
        };

        console.log(`[${requestId}] Ticket details prepared`, {
            regionId: ticketDetails.region_id,
            divisionId: ticketDetails.division_id,
            priorityId: ticketDetails.priority_id,
            hasUserId: !!ticketDetails.open_id,
            pin: ticketDetails.pin,
            subjectLength: ticketDetails.subject.length,
            detailsLength: ticketDetails.details.length
        });

        // Add retry logic for the database function call
        const maxRetries = 3;
        let insertResult = null;
        let retryCount = 0;

        while (retryCount < maxRetries) {
            try {
                const jsonTicketDetails = JSON.stringify(ticketDetails);
                const query = `SELECT public.ticket_insert($1::text) AS result;`;
                
                console.log(`[${requestId}] Executing ticket insertion (attempt ${retryCount + 1})`, {
                    queryFunction: 'public.ticket_insert',
                    payloadSize: jsonTicketDetails.length,
                    attempt: retryCount + 1
                });
                
                const result = await client.query(query, [jsonTicketDetails]);
                insertResult = result.rows[0].result;
                
                console.log(`[${requestId}] Ticket insertion function result`, {
                    success: !!insertResult,
                    result: insertResult,
                    attempt: retryCount + 1
                });

                if (insertResult) {
                    break; // Success, exit retry loop
                }

                retryCount++;
                if (retryCount < maxRetries) {
                    console.log(`[${requestId}] Retrying ticket insertion`, { attempt: retryCount + 1 });
                    await new Promise(resolve => setTimeout(resolve, 100 * retryCount)); // Exponential backoff
                }
            } catch (error) {
                console.error(`[${requestId}] Error in ticket insertion attempt ${retryCount + 1}`, {
                    error: error.message,
                    attempt: retryCount + 1
                });
                
                retryCount++;
                if (retryCount >= maxRetries) {
                    throw error;
                }
                
                await new Promise(resolve => setTimeout(resolve, 100 * retryCount)); // Exponential backoff
            }
        }
        
        if (insertResult) {
            // Enhanced verification with multiple methods
            let verifyQuery;
            let verifyParams;
            let ticketCode = null;
            
            // Method 1: Try to find by unique combination of fields (without PIN)
            console.log(`[${requestId}] Attempting ticket verification method 1 - by unique fields`);
            
            if (userId) {
                verifyQuery = `
                    SELECT code, id
                    FROM public.tickets
                    WHERE open_id = $1
                    AND subject = $2
                    AND complainant_name = $3
                    AND region_id = $4
                    AND division_id = $5
                    AND priority_id = $6
                    ORDER BY id DESC
                    LIMIT 1;
                `;
                verifyParams = [userId, ticketDetails.subject, ticketDetails.complainant_name, ticketDetails.region_id, ticketDetails.division_id, ticketDetails.priority_id];
            } else {
                verifyQuery = `
                    SELECT code, id
                    FROM public.tickets
                    WHERE open_id IS NULL
                    AND subject = $1
                    AND complainant_name = $2
                    AND region_id = $3
                    AND division_id = $4
                    AND priority_id = $5
                    AND created_by = $6
                    ORDER BY id DESC
                    LIMIT 1;
                `;
                verifyParams = [ticketDetails.subject, ticketDetails.complainant_name, ticketDetails.region_id, ticketDetails.division_id, ticketDetails.priority_id, ticketDetails.created_by];
            }
            
            let verifyResult = await client.query(verifyQuery, verifyParams);
            
            if (verifyResult.rows.length > 0) {
                ticketCode = verifyResult.rows[0].code;
                console.log(`[${requestId}] Ticket verification method 1 successful`, {
                    ticketCode,
                    ticketId: verifyResult.rows[0].id
                });
            } else {
                // Method 2: Try to find by recent timestamp and other details (fallback)
                console.log(`[${requestId}] Attempting ticket verification method 2 - by recent timestamp and details`);
                
                verifyQuery = `
                    SELECT code, id
                    FROM public.tickets
                    WHERE subject = $1
                    AND complainant_name = $2
                    AND region_id = $3
                    AND division_id = $4
                    AND priority_id = $5
                    AND date_created >= $6
                    ORDER BY id DESC
                    LIMIT 1;
                `;
                
                // Look for tickets created in the last 5 minutes
                const recentTime = new Date(Date.now() - 5 * 60 * 1000).toISOString();
                verifyParams = [ticketDetails.subject, ticketDetails.complainant_name, ticketDetails.region_id, ticketDetails.division_id, ticketDetails.priority_id, recentTime];
                
                verifyResult = await client.query(verifyQuery, verifyParams);
                
                if (verifyResult.rows.length > 0) {
                    ticketCode = verifyResult.rows[0].code;
                    console.log(`[${requestId}] Ticket verification method 2 successful`, {
                        ticketCode,
                        ticketId: verifyResult.rows[0].id
                    });
                }
            }
            
            if (ticketCode) {
                console.log(`[${requestId}] Ticket created successfully`, {
                    ticketCode,
                    verificationMethod: userId ? 'authenticated' : 'unauthenticated'
                });
                
                // Insert notification
                if (userId) {
                    console.log(`[${requestId}] Creating notification for user`, { userId });
                    try {
                        await client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [userId, `New ticket ${ticketCode} has been created successfully`]
                        );
                        console.log(`[${requestId}] Notification inserted successfully`);
                        
                        // Send push notification
                        console.log(`[${requestId}] Sending push notification`);
                        await notifyUsers([userId], 'New Ticket Created', `Your ticket ${ticketCode} has been created.`, { ticketId: ticketCode });
                        console.log(`[${requestId}] Push notification sent successfully`);
                    } catch (notificationError) {
                        console.error(`[${requestId}] Failed to create notification/push`, {
                            error: notificationError.message,
                            userId,
                            ticketCode
                        });
                        // Don't fail the entire request for notification issues
                    }
                } else {
                    console.log(`[${requestId}] Skipping notification - no authenticated user`);
                }
                
                console.log(`[${requestId}] Committing transaction`);
                await client.query('COMMIT');
                
                console.log(`[${requestId}] Ticket submission completed successfully`, {
                    ticketCode,
                    duration: Date.now() - startTime,
                    hasNotifications: !!userId
                });
                
                return res.status(201).json({
                    success: true,
                    message: 'Ticket submitted successfully',
                    ticketCode,
                    pin: ticketDetails.pin, // Include PIN for user reference
                });
            } else {
                console.error(`[${requestId}] Ticket verification failed - no ticket found in database after insertion`, {
                    subject: ticketDetails.subject,
                    complainantName: ticketDetails.complainant_name,
                    regionId: ticketDetails.region_id,
                    divisionId: ticketDetails.division_id,
                    priorityId: ticketDetails.priority_id,
                    duration: Date.now() - startTime
                });
                
                await client.query('ROLLBACK');
                return res.status(500).json({
                    success: false,
                    message: 'Failed to submit ticket: Unable to verify ticket creation in database',
                });
            }
        } else {
            console.error(`[${requestId}] Ticket insertion function returned false after all retries`, {
                functionResult: insertResult,
                retriesAttempted: retryCount,
                duration: Date.now() - startTime
            });
            
            await client.query('ROLLBACK');
            return res.status(500).json({
                success: false,
                message: 'Failed to submit ticket: Database function failed after retries',
            });
        }
    } catch (error) {
        console.error(`[${requestId}] Error during ticket submission`, {
            error: error.message,
            errorType: error.name,
            stack: error.stack,
            duration: Date.now() - startTime
        });
        
        try {
            await client.query('ROLLBACK');
            console.log(`[${requestId}] Transaction rolled back successfully`);
        } catch (rollbackError) {
            console.error(`[${requestId}] Failed to rollback transaction`, {
                rollbackError: rollbackError.message
            });
        }
        
        return res.status(500).json({
            success: false,
            message: 'Server error during ticket submission',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
        });
    } finally {
        try {
            client.release();
            console.log(`[${requestId}] Database connection released`, {
                totalDuration: Date.now() - startTime
            });
        } catch (releaseError) {
            console.error(`[${requestId}] Failed to release database connection`, {
                error: releaseError.message
            });
        }
    }
});

app.get('/notifications', authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        const userId = req.userId;
        
        const result = await client.query(
            'SELECT id, message, created_at FROM notifications WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        
        res.status(200).json({
            success: true,
            notifications: result.rows,
            count: result.rowCount
        });
    } catch (error) {
        console.error("Error fetching notifications:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching notifications",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});

app.delete('/notifications/:id', authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        const userId = req.userId;
        const notificationId = req.params.id;
        
        // Verify the notification belongs to the user before deleting
        const verifyQuery = await client.query(
            'SELECT id FROM notifications WHERE id = $1 AND user_id = $2',
            [notificationId, userId]
        );
        
        if (verifyQuery.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: "Notification not found or not owned by user"
            });
        }
        
        await client.query(
            'DELETE FROM notifications WHERE id = $1',
            [notificationId]
        );
        
        res.status(200).json({
            success: true,
            message: "Notification deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting notification:", error);
        res.status(500).json({
            success: false,
            message: "Error deleting notification",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        client.release();
    }
});



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
        await client.query('BEGIN');
        
        const updatingUserId = req.userId;
        const ticketCode = req.params.code;
        const { status } = req.body;
        
        if (!status || typeof status !== 'string' || status.trim() === '') {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                message: 'Status is required and must be a non-empty string',
                details: {
                    received: status,
                    type: typeof status
                }
            });
        }

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

        // Insert notifications into notifications table for all relevant users
        const { open_id, assigned_userid } = updateTicketQuery.rows[0];
        const notificationPromises = [];
        
        // Notify ticket creator
        if (open_id && open_id !== updatingUserId) {
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [open_id, `Your ticket ${ticketCode} status has been changed to ${statusName}`]
                )
            );
        }
        
        // Notify assigned user
        if (assigned_userid && assigned_userid !== updatingUserId && assigned_userid !== open_id) {
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [assigned_userid, `Ticket ${ticketCode} status has been changed to ${statusName}`]
                )
            );
        }
        
        // Notify the admin who made the change
        notificationPromises.push(
            client.query(
                'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                [updatingUserId, `Successfully updated ticket ${ticketCode} status to ${statusName}`]
            )
        );
        
        // Execute all notification insertions
        await Promise.all(notificationPromises);
        
        await client.query('COMMIT');

        // Send push notifications
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
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
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
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                message: "Missing required fields: code, priority_id, assigned_userid, department_id" 
            });
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

        const query = `SELECT re_assign_ticket($1::text) AS result;`;
        const result = await client.query(query, [JSON.stringify(ticketDetails)]);
        const assignmentResult = result.rows[0].result;

        if (assignmentResult === true) {
            // Insert notifications into notifications table for both users
            const notificationPromises = [];
            
            // Notify the assigned user
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [assigned_userid, `You have been assigned to ticket ${code}`]
                )
            );
            
            // Notify the assigning user (admin/manager)
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [assigningUserId, `Successfully assigned ticket ${code} to user`]
                )
            );
            
            // Get ticket creator to notify them too
            const creatorQuery = await client.query(
                'SELECT open_id FROM tickets WHERE code = $1',
                [code]
            );
            
            if (creatorQuery.rows.length > 0 && creatorQuery.rows[0].open_id) {
                const creatorId = creatorQuery.rows[0].open_id;
                if (creatorId !== assigned_userid && creatorId !== assigningUserId) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [creatorId, `Your ticket ${code} has been assigned for resolution`]
                        )
                    );
                }
            }
            
            // Execute all notification insertions
            await Promise.all(notificationPromises);
            
            // Send push notifications
            await notifyUsers([assigned_userid], 'Ticket Assigned', `You have been assigned to ticket ${code}.`, { ticketId: code });
            
            await client.query('COMMIT');
            
            res.status(200).json({
                message: "Ticket assigned successfully",
                ticket: { ...ticketDetails }
            });
        } else {
            await client.query('ROLLBACK');
            return res.status(500).json({ message: "Failed to assign ticket" });
        }
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error assigning ticket:", error);
        res.status(500).json({
            message: "Error assigning ticket",
            error: error.message
        });
    } finally {
        client.release();
    }
});

// Route to assign a ticket to a department
app.post("/tickets/assign-department", authenticateUser, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const assigningUserId = req.userId;
        const {
            code,
            priority_id,
            department_id,
            date_assigned,
            status_id,
            region_id,  // Add this to handle region_id
            division_id // Add this to handle division_id
        } = req.body;
        
        if (!code || !priority_id || !department_id) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                message: "Missing required fields: code, priority_id, department_id" 
            });
        }

        // Get the existing ticket to preserve current values
        const existingTicketQuery = await client.query(
            'SELECT * FROM tickets WHERE code = $1',
            [code]
        );
        
        if (existingTicketQuery.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ 
                message: "Ticket not found" 
            });
        }
        
        const existingTicket = existingTicketQuery.rows[0];

        // Validate department exists
        const deptCheck = await client.query(
            'SELECT dept_name FROM departments WHERE id = $1',
            [department_id]
        );
        
        if (deptCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                message: "Invalid department_id provided" 
            });
        }
        
        const departmentName = deptCheck.rows[0].dept_name;

        // Prepare ticket details for department assignment
        // Preserve existing values for required fields if not provided
        const ticketDetails = {
            code,
            priority_id,
            department_id,
            date_assigned: date_assigned || new Date().toISOString().split('T')[0],
            status_id: status_id, // Assuming 1 is "assigned" status
            is_assigned: 1, // Mark as assigned
            assigned_userid: null, // No specific user assigned for department assignment
            assigned_groupid: null, // Could be used for department if needed
            last_updated_by: assigningUserId,
            // Preserve existing values for required fields
            region_id: region_id || existingTicket.region_id, // Use existing region_id if not provided
            division_id: division_id || existingTicket.division_id, // Use existing division_id if not provided
            subject: existingTicket.subject,
            details: existingTicket.details,
            complainant_name: existingTicket.complainant_name,
            complainant_number: existingTicket.complainant_number,
            complainant_office: existingTicket.complainant_office
        };

        // Use the ticket_update function to update the ticket
        const query = `SELECT ticket_update($1::text) AS result;`;
        const result = await client.query(query, [JSON.stringify(ticketDetails)]);
        const updateResult = result.rows[0].result;

        if (updateResult === true) {
            // Get all users in the assigned department
            const departmentUsersQuery = await client.query(
                'SELECT id, first_name, surname, email, phone FROM users WHERE department_id = $1 AND status = $2',
                [department_id, '1']
            );
            
            const departmentUsers = departmentUsersQuery.rows;
            
            if (departmentUsers.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ 
                    message: `No active users found in department: ${departmentName}` 
                });
            }

            // Insert notifications for all department users
            const notificationPromises = [];
            const userIds = [];
            
            // Notify all users in the department
            departmentUsers.forEach(user => {
                notificationPromises.push(
                    client.query(
                        'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                        [user.id, `A ticket ${code} has been assigned to your department (${departmentName}). Please work on it as soon as possible.`]
                    )
                );
                userIds.push(user.id);
            });
            
            // Notify the assigning user (admin/manager)
            notificationPromises.push(
                client.query(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                    [assigningUserId, `Successfully assigned ticket ${code} to ${departmentName} department`]
                )
            );
            
            // Get ticket creator to notify them too
            const creatorQuery = await client.query(
                'SELECT open_id FROM tickets WHERE code = $1',
                [code]
            );
            
            if (creatorQuery.rows.length > 0 && creatorQuery.rows[0].open_id) {
                const creatorId = creatorQuery.rows[0].open_id;
                if (creatorId !== assigningUserId && !userIds.includes(creatorId)) {
                    notificationPromises.push(
                        client.query(
                            'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
                            [creatorId, `Your ticket ${code} has been assigned to ${departmentName} department for resolution`]
                        )
                    );
                }
            }
            
            // Execute all notification insertions
            await Promise.all(notificationPromises);
            
            // Send push notifications to all department users
            await notifyUsers(
                userIds, 
                'Department Ticket Assignment', 
                `Ticket ${code} has been assigned to your department (${departmentName}). Please work on it ASAP.`, 
                { ticketId: code, department: departmentName }
            );
            
            await client.query('COMMIT');
            
            res.status(200).json({
                message: "Ticket assigned to department successfully",
                ticket: {
                    code,
                    department_id,
                    department_name: departmentName,
                    priority_id,
                    date_assigned: ticketDetails.date_assigned,
                    status_id: ticketDetails.status_id,
                    assigned_users_count: departmentUsers.length,
                    region_id: ticketDetails.region_id,
                    division_id: ticketDetails.division_id
                },
                notified_users: departmentUsers.map(user => ({
                    id: user.id,
                    name: `${user.first_name} ${user.surname}`,
                    email: user.email,
                    phone: user.phone
                }))
            });
        } else {
            await client.query('ROLLBACK');
            return res.status(500).json({ message: "Failed to assign ticket to department" });
        }
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error assigning ticket to department:", error);
        res.status(500).json({
            message: "Error assigning ticket to department",
            error: error.message
        });
    } finally {
        client.release();
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
// Add this line near the end of your file, just before app.listen()
startAssignmentMonitoring();
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
