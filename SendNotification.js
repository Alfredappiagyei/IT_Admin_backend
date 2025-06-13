import { Expo } from 'expo-server-sdk';

// Initialize Expo SDK client
const expo = new Expo({
  accessToken: process.env.EXPO_ACCESS_TOKEN, // Optional, set in .env if push security is enabled
  useFcmV1: true, // Use FCM v1 (default)
});

// Send push notifications
export async function sendPushNotification(pushTokens, title, body, data = {}) {
  const messages = [];

  // Validate push tokens
  for (const pushToken of pushTokens) {
    if (!Expo.isExpoPushToken(pushToken)) {
      console.error(`Push token ${pushToken} is not a valid Expo push token`);
      continue;
    }

    messages.push({
      to: pushToken,
      sound: 'default',
      title,
      body,
      data,
      priority: 'high', // Ensure high priority for immediate delivery
    });
  }

  // Batch notifications
  const chunks = expo.chunkPushNotifications(messages);
  const tickets = [];

  // Send notifications
  for (const chunk of chunks) {
    try {
      const ticketChunk = await expo.sendPushNotificationsAsync(chunk);
      tickets.push(...ticketChunk);
      console.log('Notifications sent:', ticketChunk);
    } catch (error) {
      console.error('Error sending notifications:', error);
    }
  }

  // Handle receipts
  await handlePushReceipts(tickets);
}

// Handle push receipts
async function handlePushReceipts(tickets) {
  const receiptIds = tickets
    .filter(ticket => ticket.status === 'ok' && ticket.id)
    .map(ticket => ticket.id);

  if (receiptIds.length === 0) return;

  const receiptIdChunks = expo.chunkPushNotificationReceiptIds(receiptIds);

  for (const chunk of receiptIdChunks) {
    try {
      const receipts = await expo.getPushNotificationReceiptsAsync(chunk);
      for (const receiptId in receipts) {
        const { status, details } = receipts[receiptId];
        if (status === 'ok') {
          console.log(`Notification ${receiptId} delivered successfully`);
        } else if (status === 'error') {
          console.error(`Notification ${receiptId} failed:`, details.error);
          // Handle errors (e.g., DeviceNotRegistered, InvalidCredentials)
          if (details.error === 'DeviceNotRegistered') {
            // Remove invalid token from database
            console.log(`Removing invalid token: ${details.pushToken}`);
          }
        }
      }
    } catch (error) {
      console.error('Error fetching receipts:', error);
    }
  }
}