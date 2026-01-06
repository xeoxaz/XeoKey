import { getDatabase } from '../db/mongodb';
import { ObjectId } from 'mongodb';
import { analyticsLogger } from '../utils/logger';

export interface AnalyticsEvent {
  _id?: string;
  userId: string;
  eventType: 'add' | 'delete' | 'edit' | 'copy' | 'view' | 'error';
  timestamp: Date;
  metadata?: {
    entryId?: string;
    errorMessage?: string;
    [key: string]: any;
  };
}

// Track an analytics event
export async function trackEvent(
  userId: string,
  eventType: AnalyticsEvent['eventType'],
  metadata?: AnalyticsEvent['metadata']
): Promise<void> {
  try {
    const db = getDatabase();
    const analyticsCollection = db.collection<AnalyticsEvent>('analytics');

    const event: AnalyticsEvent = {
      userId,
      eventType,
      timestamp: new Date(),
      metadata: metadata || {},
    };

    await analyticsCollection.insertOne(event);
  } catch (error) {
    analyticsLogger.error(`Error tracking analytics event: ${error}`);
    // Don't throw - analytics failures shouldn't break the app
  }
}

// Get analytics data for a user within a time range
export async function getAnalyticsData(
  userId: string,
  startDate: Date,
  endDate: Date
): Promise<{
  adds: number;
  deletes: number;
  edits: number;
  copies: number;
  views: number;
  errors: number;
  dailyData: Array<{
    date: string;
    adds: number;
    deletes: number;
    edits: number;
    copies: number;
    views: number;
    errors: number;
  }>;
}> {
  const db = getDatabase();
  const analyticsCollection = db.collection<AnalyticsEvent>('analytics');

  // Convert userId to string if needed
  const userIdString = typeof userId === 'string' ? userId : (userId as any).toString();

  // Query events in the date range
  let query: any = {
    userId: userIdString,
    timestamp: { $gte: startDate, $lte: endDate },
  };

  const events = await analyticsCollection.find(query).toArray();

  // If no results with string userId, try ObjectId
  if (events.length === 0 && ObjectId.isValid(userIdString)) {
    query = {
      userId: new ObjectId(userIdString),
      timestamp: { $gte: startDate, $lte: endDate },
    };
    const eventsWithObjectId = await analyticsCollection.find(query).toArray();
    events.push(...eventsWithObjectId);
  }

  // Aggregate by event type
  const totals = {
    adds: 0,
    deletes: 0,
    edits: 0,
    copies: 0,
    views: 0,
    errors: 0,
  };

  // Group by date
  const dailyMap = new Map<string, typeof totals>();

  events.forEach((event) => {
    const dateKey = event.timestamp.toISOString().split('T')[0];

    if (!dailyMap.has(dateKey)) {
      dailyMap.set(dateKey, { ...totals });
    }

    const dayData = dailyMap.get(dateKey)!;
    totals[event.eventType]++;
    dayData[event.eventType]++;
  });

  // Fill in missing days with zero values to ensure continuous graph
  const filledDailyData: Array<{
    date: string;
    adds: number;
    deletes: number;
    edits: number;
    copies: number;
    views: number;
    errors: number;
  }> = [];

  const currentDate = new Date(startDate);
  const endDateObj = new Date(endDate);

  // Generate all days in the range
  while (currentDate <= endDateObj) {
    const dateKey = currentDate.toISOString().split('T')[0];
    const dayData = dailyMap.get(dateKey) || { ...totals };
    filledDailyData.push({
      date: dateKey,
      ...dayData
    });
    currentDate.setDate(currentDate.getDate() + 1);
  }

  // Sort by date
  filledDailyData.sort((a, b) => a.date.localeCompare(b.date));

  return {
    ...totals,
    dailyData: filledDailyData,
  };
}

