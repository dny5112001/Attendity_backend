const express = require("express");
const mysql = require("mysql");
const app = express();
const port = 3000;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");

// Middleware
app.use(express.json());
// Enable CORS for all routes
app.use(cors());

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "123456",
  database: "Attendity",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL");
});

// Create Employee table
const createEmployeeTable = `
CREATE TABLE IF NOT EXISTS Employee (
    EmpId INT AUTO_INCREMENT PRIMARY KEY,
    Department VARCHAR(100) NOT NULL,
    Designation VARCHAR(100) NOT NULL,
    DateOfJoining DATE NOT NULL,
    Password VARCHAR(255) NOT NULL,
    DeviceId VARCHAR(255)
);
`;

db.query(createEmployeeTable, (err, result) => {
  if (err) {
    console.error("Error creating Employee table:", err);
  } else {
    console.log("Employee table created or already exists.");
  }
});

// Create User table with profile picture column
const createUserTable = `
CREATE TABLE IF NOT EXISTS User (
    EmpId INT,
    FirstName VARCHAR(100) NOT NULL,
    LastName VARCHAR(100) NOT NULL,
    Email VARCHAR(100) UNIQUE NOT NULL,
    Phone VARCHAR(15) NOT NULL,
    ProfilePic BLOB, -- Column to store profile picture in binary format
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (EmpId) REFERENCES Employee(EmpId)
);
`;

db.query(createUserTable, (err, result) => {
  if (err) {
    console.error("Error creating User table:", err);
  } else {
    console.log("User table created or already exists.");
  }
});

// Create Attendance table
const createAttendanceTable = `
CREATE TABLE IF NOT EXISTS Attendance (
    EmpId INT,
    CheckIn TIME NOT NULL,
    CheckOut TIME,
    CheckInLatitude DECIMAL(10, 8),
    CheckInLongitude DECIMAL(11, 8),
    CheckOutLatitude DECIMAL(10, 8),
    CheckOutLongitude DECIMAL(11, 8),
    Date DATE NOT NULL,
    DeviceId VARCHAR(255),
    WorkDuration TIME AS (TIMEDIFF(CheckOut, CheckIn)),
    FOREIGN KEY (EmpId) REFERENCES Employee(EmpId)
);
`;

db.query(createAttendanceTable, (err, result) => {
  if (err) {
    console.error("Error creating Attendance table:", err);
  } else {
    console.log("Attendance table created or already exists.");
  }
});

const createLeaveTable = `
CREATE TABLE IF NOT EXISTS \`Leave\` (
    LeaveId INT AUTO_INCREMENT PRIMARY KEY,
    EmpId INT NOT NULL,  -- Add EmpId to the Leave table
    LeaveType VARCHAR(100) NOT NULL,
    StartDate DATE NOT NULL,
    EndDate DATE NOT NULL,
    LeaveStatus VARCHAR(50) NOT NULL,
    LeaveReason VARCHAR(255) NOT NULL,
    ApprovedBy INT,
    FOREIGN KEY (EmpId) REFERENCES User(EmpId),  -- Foreign key referencing EmpId from User table
    FOREIGN KEY (ApprovedBy) REFERENCES User(EmpId) -- Foreign key for ApprovedBy referencing EmpId from User table
);
`;
db.query(createLeaveTable, (err, result) => {
  if (err) {
    console.error("Error creating Leave table:", err);
  } else {
    console.log("Leave table created or already exists.");
  }
});

// Create Geofence table
const createGeofenceTable = `
CREATE TABLE IF NOT EXISTS Geofence (
    OfficeLatitude DECIMAL(10, 8) NOT NULL,
    OfficeLongitude DECIMAL(11, 8) NOT NULL
);
`;

db.query(createGeofenceTable, (err, result) => {
  if (err) {
    console.error("Error creating Geofence table:", err);
  } else {
    console.log("Geofence table created or already exists.");
  }
});

// Create Peer Attendance table
const createPeerAttendanceTable = `
CREATE TABLE IF NOT EXISTS PeerAttendance (
    EmpId INT NOT NULL,
    PeerEmpId INT NOT NULL,
    CheckInTime DATETIME NOT NULL,
    Date DATE NOT NULL,
    FOREIGN KEY (EmpId) REFERENCES Employee(EmpId),
    FOREIGN KEY (PeerEmpId) REFERENCES Employee(EmpId)
);
`;

db.query(createPeerAttendanceTable, (err, result) => {
  if (err) {
    console.error("Error creating Peer Attendance table:", err);
  } else {
    console.log("Peer Attendance table created or already exists.");
  }
});

// Create Notification table
const createNotificationTable = `
CREATE TABLE IF NOT EXISTS Notification (
    EmpId INT NOT NULL,
    Message TEXT NOT NULL,
    TypeOfMessage VARCHAR(100) NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Date DATE NOT NULL,
    WorkImage VARCHAR(255),
    WorkImageSendingTime DATETIME,
    FOREIGN KEY (EmpId) REFERENCES Employee(EmpId)
);
`;

db.query(createNotificationTable, (err, result) => {
  if (err) {
    console.error("Error creating Notification table:", err);
  } else {
    console.log("Notification table created or already exists.");
  }
});

const createSOSTable = `
CREATE TABLE IF NOT EXISTS SOS (
  SOSId INT AUTO_INCREMENT PRIMARY KEY,
  EmpId INT NOT NULL,
  Time TIME NOT NULL,
  Date DATE NOT NULL,
  RecipientContactNumbers VARCHAR(255) NOT NULL, -- Storing recipient numbers as a comma-separated string
  FOREIGN KEY (EmpId) REFERENCES Employee(EmpId)
);
`;

db.query(createSOSTable, (err, result) => {
  if (err) {
    console.error("Error creating SOS table:", err);
  } else {
    console.log("SOS table created or already exists.");
  }
});

// All the Api's are here

const SECRET_KEY = "your_secret_key"; // Use a secure key, don't hardcode this in production

// Set up Multer storage configuration
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post("/register", upload.single("profilePic"), async (req, res) => {
  const {
    FirstName,
    LastName,
    Email,
    Phone,
    Password,
    Department,
    Designation,
    DateOfJoining,
    DeviceId,
  } = req.body;

  const profilePic = req.file ? req.file.buffer : null; // Get profile pic from request

  // Check if user already exists
  const checkUserQuery = "SELECT * FROM User WHERE Email = ?";
  db.query(checkUserQuery, [Email], async (err, result) => {
    if (err) {
      console.error("Error checking user:", err);
      return res.status(500).send("Server error");
    }

    if (result.length > 0) {
      return res.status(400).send("User with this email already exists.");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(Password, 10);

    // Create new employee record
    const insertEmployeeQuery = `
      INSERT INTO Employee (Department, Designation, DateOfJoining, Password, DeviceId)
      VALUES (?, ?, ?, ?, ?)
    `;
    db.query(
      insertEmployeeQuery,
      [Department, Designation, DateOfJoining, hashedPassword, DeviceId],
      (err, result) => {
        if (err) {
          console.error("Error creating employee:", err);
          return res.status(500).send("Server error");
        }

        const EmpId = result.insertId; // Get the EmpId of the inserted employee

        // Create new user record with profile image as BLOB
        const insertUserQuery = `
          INSERT INTO User (EmpId, FirstName, LastName, Email, Phone, ProfilePic)
          VALUES (?, ?, ?, ?, ?, ?)
        `;
        db.query(
          insertUserQuery,
          [EmpId, FirstName, LastName, Email, Phone, profilePic], // Insert the profile image as BLOB
          (err, result) => {
            if (err) {
              console.error("Error creating user:", err);
              return res.status(500).send("Server error");
            }

            // Create JWT Token with EmpId
            const token = jwt.sign({ EmpId }, SECRET_KEY);

            // Send response with token
            return res.status(201).send({
              message: "User registered successfully",
              token: token, // Send the token back to the user
            });
          }
        );
      }
    );
  });
});

//Login

app.post("/login", (req, res) => {
  const { Email, Password } = req.body;

  // Check if email and password are provided
  if (!Email || !Password) {
    return res.status(400).send("Email and Password are required");
  }

  // Step 1: Check if the email exists in the User table and get EmpId
  const checkUserQuery = "SELECT * FROM User WHERE Email = ?";
  db.query(checkUserQuery, [Email], (err, result) => {
    if (err) {
      console.error("Error checking user:", err);
      return res.status(500).send("Server error");
    }

    if (result.length === 0) {
      return res.status(400).send("Invalid email or password");
    }

    const user = result[0];

    // Step 2: Use the EmpId to get the password from the Employee table
    const getEmployeePasswordQuery =
      "SELECT Password FROM Employee WHERE EmpId = ?";
    db.query(getEmployeePasswordQuery, [user.EmpId], async (err, empResult) => {
      if (err) {
        console.error("Error fetching employee password:", err);
        return res.status(500).send("Server error");
      }

      if (empResult.length === 0) {
        return res.status(400).send("Invalid email or password");
      }

      const employee = empResult[0];

      // Step 3: Compare the plain-text password with the hashed password from Employee table
      try {
        const isMatch = await bcrypt.compare(Password, employee.Password);
        if (!isMatch) {
          return res.status(400).send("Invalid email or password");
        }

        // Step 4: Create JWT token and send response
        const token = jwt.sign({ EmpId: user.EmpId }, SECRET_KEY);

        const { EmpId, FirstName, LastName, Email, Phone } = user;
        return res.status(200).send({
          message: "Login successful",
          user: { EmpId, FirstName, LastName, Email, Phone },
          token: token,
        });
      } catch (err) {
        console.error("Error comparing password:", err);
        return res.status(500).send("Error comparing password");
      }
    });
  });
});

// Middleware to verify token and extract EmpId
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Assuming token is in the format "Bearer <token>"

  if (!token) {
    return res.status(403).json({ message: "No token provided." });
  }

  jwt.verify(token, "your_secret_key", (err, decoded) => {
    // Replace 'your_jwt_secret' with your secret key
    if (err) {
      return res.status(401).json({ message: "Invalid token." });
    }

    // Attach EmpId to the request object
    req.EmpId = decoded.EmpId;
    next();
  });
};

// Endpoint to apply for leave
app.post("/applyLeave", verifyToken, (req, res) => {
  const { LeaveType, StartDate, EndDate, LeaveStatus, LeaveReason } = req.body;
  const EmpId = req.EmpId; // Extracted EmpId from the decoded token

  // Validate input fields
  if (
    !EmpId ||
    !LeaveType ||
    !StartDate ||
    !EndDate ||
    !LeaveStatus ||
    !LeaveReason
  ) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields." });
  }

  // SQL query to insert the leave request into the Leave table
  const query = `
    INSERT INTO \`Leave\` (EmpId, LeaveType, StartDate, EndDate, LeaveStatus, LeaveReason)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  // Values to be inserted into the query
  const values = [
    EmpId,
    LeaveType,
    StartDate,
    EndDate,
    LeaveStatus,
    LeaveReason,
  ];

  // Execute the query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Error applying leave:", err);
      return res
        .status(500)
        .json({ message: "An error occurred while applying leave." });
    }

    // Respond with success message
    res.status(200).json({
      message: "Leave applied successfully!",
      leaveId: result.insertId,
    });
  });
});

// Adding SOS data to the table

app.post("/addSOS", verifyToken, (req, res) => {
  const { RecipientContactNumbers } = req.body;

  // Validate required field
  if (!RecipientContactNumbers) {
    return res
      .status(400)
      .json({ message: "RecipientContactNumbers is required" });
  }

  // Get EmpId from the request object (set by verifyToken middleware)
  const EmpId = req.EmpId;

  // Automatically calculate the current date and time
  const currentDate = new Date();
  const DateStr = currentDate.toISOString().split("T")[0]; // Format: YYYY-MM-DD
  const TimeStr = currentDate.toISOString().split("T")[1].split(".")[0]; // Format: HH:mm:ss

  // SQL query to insert SOS data
  const insertSOSQuery = `
    INSERT INTO SOS (EmpId, Time, Date, RecipientContactNumbers)
    VALUES (?, ?, ?, ?)
  `;

  db.query(
    insertSOSQuery,
    [EmpId, TimeStr, DateStr, RecipientContactNumbers],
    (err, result) => {
      if (err) {
        console.error("Error inserting SOS data:", err);
        return res.status(500).json({ message: "Server error" });
      }

      return res.status(201).json({
        message: "SOS data added successfully",
        SOSId: result.insertId, // Return the inserted SOS ID
      });
    }
  );
});

// API endpoint to get profile picture
app.get("/getProfilePic", verifyToken, (req, res) => {
  const EmpId = req.EmpId;

  const query = "SELECT ProfilePic FROM User WHERE EmpId = ?";
  db.query(query, [EmpId], (err, result) => {
    if (err) {
      console.error("Error fetching profile picture:", err);
      return res
        .status(500)
        .json({ message: "Error fetching profile picture." });
    }

    if (result.length === 0 || !result[0].ProfilePic) {
      return res.status(404).json({ message: "Profile picture not found." });
    }

    // Convert BLOB to base64
    const profilePicBase64 = result[0].ProfilePic.toString("base64");

    // Send as data URI
    res.json({ profilePic: `data:image/png;base64,${profilePicBase64}` }); // Adjust MIME type if needed
  });
});

// Endpoint to add check-in time
app.post("/checkin", verifyToken, (req, res) => {
  const { checkInLatitude, checkInLongitude, DeviceId } = req.body;
  const EmpId = req.EmpId; // From token

  // Step 1: Validate the Device ID from the Employee table
  const queryCheckDeviceId = "SELECT DeviceId FROM Employee WHERE EmpId = ?";

  db.query(queryCheckDeviceId, [EmpId], (err, result) => {
    if (err) {
      console.error("Error fetching device ID:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Employee not found." });
    }

    const storedDeviceId = result[0].DeviceId;

    // Check if the device IDs match
    if (storedDeviceId !== DeviceId) {
      return res.status(403).json({ message: "Invalid Device ID." });
    }

    // Step 2: If the Device ID matches, insert the check-in data
    const currentDate = new Date().toISOString().split("T")[0]; // Format: YYYY-MM-DD

    // If checkInTime is in 12-hour format, convert it to 24-hour format (HH:MM:SS)
    const checkInTime = new Date();
    const formattedCheckInTime = checkInTime.toTimeString().split(" ")[0]; // Extracts the 'HH:MM:SS' part of the time string

    const queryInsertCheckIn = `
      INSERT INTO Attendance (EmpId, CheckIn, Date, CheckInLatitude, CheckInLongitude, DeviceId)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    const values = [
      EmpId,
      formattedCheckInTime, // Use the correctly formatted time
      currentDate,
      checkInLatitude,
      checkInLongitude,
      DeviceId,
    ];

    db.query(queryInsertCheckIn, values, (err, result) => {
      if (err) {
        console.error("Error inserting check-in data:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      res.status(200).json({ message: "Check-in recorded successfully." });
    });
  });
});

// Endpoint to handle employee checkout
app.post("/checkOut", verifyToken, (req, res) => {
  const { EmpId } = req;
  const { checkOutLatitude, checkOutLongitude, DeviceId } = req.body;

  // Validate if the employee exists and check if the deviceId matches
  db.query(
    "SELECT * FROM Employee WHERE EmpId = ?",
    [EmpId],
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error checking employee data." });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "Employee not found." });
      }

      const employee = results[0];
      if (employee.DeviceId !== DeviceId) {
        return res.status(403).json({ message: "Device ID mismatch." });
      }

      const checkOutTime = new Date();
      const formattedCheckOutTime = checkOutTime.toTimeString().split(" ")[0]; // Extracts the 'HH:MM:SS' part of the time string
      // Update the attendance table with the checkout details
      db.query(
        `UPDATE Attendance
       SET CheckOut = ?, CheckOutLatitude = ?, CheckOutLongitude = ?
       WHERE EmpId = ? AND Date = CURDATE() AND CheckOut IS NULL`,
        [formattedCheckOutTime, checkOutLatitude, checkOutLongitude, EmpId],
        (updateErr, updateResults) => {
          if (updateErr) {
            return res
              .status(500)
              .json({ message: "Error updating checkout data." });
          }

          if (updateResults.affectedRows === 0) {
            return res
              .status(400)
              .json({ message: "Checkout not found for today." });
          }

          return res
            .status(200)
            .json({ message: "Checkout recorded successfully." });
        }
      );
    }
  );
});

app.get("/attendance", verifyToken, (req, res) => {
  const { EmpId } = req; // The employee ID from the token

  // Query the database to get the check-in and check-out times for the employee
  db.query(
    "SELECT CheckIn, CheckOut FROM Attendance WHERE EmpId = ? AND Date = CURDATE()",
    [EmpId],
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error fetching attendance data." });
      }

      console.log(results);

      if (results.length === 0) {
        return res
          .status(404)
          .json({ message: "No attendance records found." });
      }

      // Send the check-in and check-out data back to the client
      res.status(200).json({ attendance: results });
    }
  );
});
app.get("/getProfile", verifyToken, (req, res) => {
  const { EmpId } = req; // Get the EmpId from the token (assumed to be verified)

  // Query to join Employee and User tables to get user profile data
  const getProfileQuery = `
    SELECT 
      e.EmpId, 
      e.Department, 
      e.Designation, 
      e.DateOfJoining, 
      u.FirstName, 
      u.LastName, 
      u.Email, 
      u.Phone, 
      u.ProfilePic, 
      u.CreatedAt
    FROM 
      Employee e
    JOIN 
      User u ON e.EmpId = u.EmpId
    WHERE 
      e.EmpId = ?
  `;

  db.query(getProfileQuery, [EmpId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching profile data." });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Employee not found." });
    }

    const userProfile = results[0];

    // If ProfilePic exists, encode it to Base64
    if (userProfile.ProfilePic) {
      userProfile.ProfilePic = `data:image/png;base64,${Buffer.from(
        userProfile.ProfilePic
      ).toString("base64")}`;
    }

    return res.status(200).json({
      message: "Profile fetched successfully.",
      profile: userProfile,
    });
  });
});

app.get("/getAllusers", (req, res) => {
  const query = `
        SELECT 
            e.EmpId, 
            e.Department, 
            e.Designation, 
            u.FirstName, 
            u.LastName, 
            u.Email, 
            u.Phone, 
            u.ProfilePic
        FROM 
            Employee e
        INNER JOIN 
            User u
        ON 
            e.EmpId = u.EmpId
    `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching user information:", err);
      res.status(500).json({ error: "Failed to fetch user information" });
    } else {
      // Convert BLOB to base64 for ProfilePic
      const formattedResults = results.map((user) => ({
        ...user,
        ProfilePic: user.ProfilePic ? user.ProfilePic.toString("base64") : null,
      }));
      res.status(200).json(formattedResults);
    }
  });
});

const connectedUsers = {}; // To store connected users and their socket IDs

// Create server and socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Adjust according to your app's URL
    methods: ["GET", "POST"],
  },
});

// Handle socket connection
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  // Register user with token
  socket.on("register", ({ token }) => {
    try {
      const decoded = jwt.verify(token, "your_secret_key");
      const empId = decoded.EmpId;
      connectedUsers[empId] = socket.id;
      console.log("User registered:", empId, socket.id);
    } catch (error) {
      console.error("Invalid token:", error);
      socket.disconnect();
    }
  });

  // Handle notification sending
  socket.on("send-notification", ({ targetEmpId, message }) => {
    const targetSocketId = connectedUsers[targetEmpId];
    const currentDate = new Date();
    const formattedDate = currentDate.toISOString().split("T")[0]; // Format as YYYY-MM-DD

    // Insert notification into the database
    const query = `
      INSERT INTO Notification (EmpId, Message, TypeOfMessage, Date)
      VALUES (?, ?, ?, ?)
    `;
    const values = [targetEmpId, message, "WorkImageRequest", formattedDate];

    db.query(query, values, (err, result) => {
      if (err) {
        console.error("Error inserting notification:", err);
        return;
      }
      console.log("Notification inserted into the database.");
    });

    // If the user is connected, send the notification
    if (targetSocketId) {
      io.to(targetSocketId).emit("notification", { message });
      console.log("Notification sent to user:", targetEmpId);
    } else {
      console.log("User not connected:", targetEmpId);
    }
  });

  // Clean up on disconnect
  socket.on("disconnect", () => {
    console.log("A user disconnected:", socket.id);
    for (const empId in connectedUsers) {
      if (connectedUsers[empId] === socket.id) {
        delete connectedUsers[empId];
        console.log("User disconnected:", empId);
      }
    }
  });
});

// // Start server
// app.listen(port, () => {
//   console.log(`Server running on http://localhost:${port}`);
// });
// Start both API and WebSocket server on the same port
server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
