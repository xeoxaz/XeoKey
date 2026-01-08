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

  // Build query with $or to handle both string and ObjectId userId formats in one query
  const userIdConditions: any[] = [{ userId: userIdString }];
  if (ObjectId.isValid(userIdString)) {
    userIdConditions.push({ userId: new ObjectId(userIdString) });
  }

  // Use MongoDB aggregation pipeline for efficient processing
  const pipeline = [
    // Match events for this user in the date range
    {
      $match: {
        $or: userIdConditions,
        timestamp: { $gte: startDate, $lte: endDate },
      },
    },
    // Group by date and event type
    {
      $group: {
        _id: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          eventType: '$eventType',
        },
        count: { $sum: 1 },
      },
    },
    // Reshape to group by date
    {
      $group: {
        _id: '$_id.date',
        adds: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'add'] }, '$count', 0] } },
        deletes: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'delete'] }, '$count', 0] } },
        edits: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'edit'] }, '$count', 0] } },
        copies: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'copy'] }, '$count', 0] } },
        views: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'view'] }, '$count', 0] } },
        errors: { $sum: { $cond: [{ $eq: ['$_id.eventType', 'error'] }, '$count', 0] } },
      },
    },
    // Rename _id to date
    {
      $project: {
        _id: 0,
        date: '$_id',
        adds: { $ifNull: ['$adds', 0] },
        deletes: { $ifNull: ['$deletes', 0] },
        edits: { $ifNull: ['$edits', 0] },
        copies: { $ifNull: ['$copies', 0] },
        views: { $ifNull: ['$views', 0] },
        errors: { $ifNull: ['$errors', 0] },
      },
    },
  ];

  const aggregatedResults = await analyticsCollection.aggregate(pipeline).toArray();

  // Calculate totals
  const totals = {
    adds: 0,
    deletes: 0,
    edits: 0,
    copies: 0,
    views: 0,
    errors: 0,
  };

  // Create map of daily data
  const dailyMap = new Map<string, typeof totals>();
  for (const result of aggregatedResults) {
    dailyMap.set(result.date, {
      adds: result.adds || 0,
      deletes: result.deletes || 0,
      edits: result.edits || 0,
      copies: result.copies || 0,
      views: result.views || 0,
      errors: result.errors || 0,
    });

    // Sum totals
    totals.adds += result.adds || 0;
    totals.deletes += result.deletes || 0;
    totals.edits += result.edits || 0;
    totals.copies += result.copies || 0;
    totals.views += result.views || 0;
    totals.errors += result.errors || 0;
  }

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
    const dayData = dailyMap.get(dateKey) || { ...totals, adds: 0, deletes: 0, edits: 0, copies: 0, views: 0, errors: 0 };
    filledDailyData.push({
      date: dateKey,
      ...dayData,
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

