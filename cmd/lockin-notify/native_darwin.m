//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <UserNotifications/UserNotifications.h>
#import <CoreServices/CoreServices.h>
#import "native.h"
#import "_cgo_export.h"

static NSString *const ReminderID = @"lockin-reminder";
static NSString *const ResultID = @"lockin-result";
static BOOL AuthorizeOnLaunch;
static BOOL StatusOnly;
static BOOL AuthorizationInFlight;
static BOOL ReminderInFlight;
static unsigned long long ReminderGeneration;

static void Complete(unsigned long long token, NSString *value, NSError *error) {
    goNativeComplete(token, (char *)[(value ?: @"") UTF8String],
                     (char *)[(error.localizedDescription ?: @"") UTF8String]);
}

static NSError *Failure(NSString *message) {
    return [NSError errorWithDomain:@"local.lockin.notifications" code:1
                          userInfo:@{NSLocalizedDescriptionKey: message}];
}

static void ClearReminder(void) {
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    [center removePendingNotificationRequestsWithIdentifiers:@[ReminderID]];
    [center removeDeliveredNotificationsWithIdentifiers:@[ReminderID]];
}

static void Authorize(void) {
    if (StatusOnly || AuthorizationInFlight) return;
    AuthorizationInFlight = YES;
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
        dispatch_async(dispatch_get_main_queue(), ^{
            // Denial is never retried, even through the explicit authorization URL.
            if (settings.authorizationStatus != UNAuthorizationStatusNotDetermined) {
                AuthorizationInFlight = NO;
                return;
            }
            [center requestAuthorizationWithOptions:UNAuthorizationOptionAlert
                                  completionHandler:^(BOOL granted, NSError *error) {
                if (error) NSLog(@"Lockin notification authorization failed: %@", error.localizedDescription);
                dispatch_async(dispatch_get_main_queue(), ^{ AuthorizationInFlight = NO; });
            }];
        });
    }];
}

@interface LockinDelegate : NSObject <NSApplicationDelegate, UNUserNotificationCenterDelegate>
@end

@implementation LockinDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    if (AuthorizeOnLaunch) Authorize();
}

- (void)application:(NSApplication *)application openURLs:(NSArray<NSURL *> *)urls {
    for (NSURL *url in urls) {
        if ([url.scheme isEqualToString:@"lockin-alerts"] &&
            [url.host isEqualToString:@"authorize"] &&
            (url.path.length == 0 || [url.path isEqualToString:@"/"]) &&
            url.query == nil && url.fragment == nil && url.user == nil && url.port == nil) {
            Authorize();
        }
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application {
    return NO;
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
      willPresentNotification:(UNNotification *)notification
        withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
    completionHandler(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList);
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
 didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completionHandler {
    // Ordinary clicks and dismissals must never start a session. The persisted userInfo
    // survives helper relaunch; the daemon, not the helper, authorizes this offer.
    if ([response.actionIdentifier isEqualToString:@"start-session"] &&
        [response.notification.request.identifier isEqualToString:ReminderID]) {
        id offerID = response.notification.request.content.userInfo[@"alert_id"];
        if ([offerID isKindOfClass:[NSString class]] && [offerID length] > 0) {
            goNativeAction((char *)[offerID UTF8String]);
        }
    }
    completionHandler();
}
@end

static LockinDelegate *Delegate;

int lockin_native_init(int authorize, int status_only) {
    @autoreleasepool {
        NSBundle *bundle = [NSBundle mainBundle];
        if (![bundle.bundleIdentifier isEqualToString:@"local.lockin.notifications"]) return 1;
        AuthorizeOnLaunch = authorize != 0;
        StatusOnly = status_only != 0;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        Delegate = [[LockinDelegate alloc] init];
        [NSApp setDelegate:Delegate];
        [UNUserNotificationCenter currentNotificationCenter].delegate = Delegate;
        if (!StatusOnly) {
            // LaunchAgents execute the bundle binary directly, bypassing LaunchServices.
            // Register the URL handler without opening a window or requesting permission.
            OSStatus status = LSRegisterURL((CFURLRef)bundle.bundleURL, true);
            if (status != noErr) NSLog(@"Lockin bundle registration failed: %d", (int)status);
        }
        return 0;
    }
}

void lockin_native_run(void) {
    @autoreleasepool { [NSApp run]; }
}

void lockin_native_stop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp stop:nil];
        // stop: alone does not wake an idle NSApplication event loop.
        NSEvent *event = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
            location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0 context:nil
            subtype:0 data1:0 data2:0];
        [NSApp postEvent:event atStart:YES];
    });
}

void lockin_native_settings(unsigned long long token) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UNUserNotificationCenter currentNotificationCenter]
            getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
                NSString *permission = @"unknown";
                switch (settings.authorizationStatus) {
                    case UNAuthorizationStatusNotDetermined: permission = @"not_determined"; break;
                    case UNAuthorizationStatusDenied: permission = @"denied"; break;
                    case UNAuthorizationStatusAuthorized: permission = @"authorized"; break;
                    case UNAuthorizationStatusProvisional: permission = @"provisional"; break;
                    default: break;
                }
                Complete(token, permission, nil);
            }];
    });
}

void lockin_native_clear(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        ReminderGeneration++;
        ClearReminder();
    });
}

void lockin_native_reminder(unsigned long long token, const char *offer_id,
                           const char *message, const char *label) {
    @autoreleasepool {
        // NSString conversion copies every C input before Go frees its buffers.
        NSString *offerID = [NSString stringWithUTF8String:offer_id];
        NSString *body = [NSString stringWithUTF8String:message];
        NSString *title = [NSString stringWithUTF8String:label];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!offerID.length || !body.length || !title.length || ReminderInFlight) {
                Complete(token, nil, Failure(@"Invalid or overlapping notification submission"));
                return;
            }
            ReminderInFlight = YES;
            unsigned long long generation = ++ReminderGeneration;
            UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
            ClearReminder();
            // Unique categories keep an old notice from acquiring a newer offer's title.
            NSString *categoryID = [@"lockin-start-" stringByAppendingString:offerID];
            UNNotificationAction *action = [UNNotificationAction actionWithIdentifier:@"start-session"
                title:title options:UNNotificationActionOptionNone];
            UNNotificationCategory *category = [UNNotificationCategory categoryWithIdentifier:categoryID
                actions:@[action] intentIdentifiers:@[] options:UNNotificationCategoryOptionNone];
            [center setNotificationCategories:[NSSet setWithObject:category]];
            UNMutableNotificationContent *content = [[[UNMutableNotificationContent alloc] init] autorelease];
            content.title = @"Lockin";
            content.body = body;
            content.categoryIdentifier = categoryID;
            content.userInfo = @{ @"alert_id": offerID };
            UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:ReminderID
                content:content trigger:nil];
            [center addNotificationRequest:request withCompletionHandler:^(NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    ReminderInFlight = NO;
                    if (generation != ReminderGeneration) {
                        ClearReminder();
                        Complete(token, nil, Failure(@"Notification was cleared before delivery completed"));
                    } else {
                        Complete(token, nil, error);
                    }
                });
            }];
        });
    }
}

void lockin_native_result(unsigned long long token, const char *message) {
    @autoreleasepool {
        NSString *body = [NSString stringWithUTF8String:message];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!body.length) {
                Complete(token, nil, Failure(@"Empty session result"));
                return;
            }
            UNMutableNotificationContent *content = [[[UNMutableNotificationContent alloc] init] autorelease];
            content.title = @"Lockin session";
            content.body = body;
            // No category or userInfo: result notifications can never start sessions.
            UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:ResultID
                content:content trigger:nil];
            [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:request
                withCompletionHandler:^(NSError *error) { Complete(token, nil, error); }];
        });
    }
}
