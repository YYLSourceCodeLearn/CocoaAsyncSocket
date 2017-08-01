//
//  GCDAsyncSocket.m
//  
//  This class is in the public domain.
//  Originally created by Robbie Hanson in Q4 2010.
//  Updated and maintained by Deusty LLC and the Apple development community.
//
//  https://github.com/robbiehanson/CocoaAsyncSocket
//

#import "GCDAsyncSocket.h"

#if TARGET_OS_IPHONE
#import <CFNetwork/CFNetwork.h>
#endif

#import <TargetConditionals.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <netinet/in.h>
#import <net/if.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <sys/poll.h>
#import <sys/uio.h>
#import <sys/un.h>
#import <unistd.h>

#if ! __has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
// For more information see: https://github.com/robbiehanson/CocoaAsyncSocket/wiki/ARC
#endif


#ifndef GCDAsyncSocketLoggingEnabled
#define GCDAsyncSocketLoggingEnabled 0
#endif

#if GCDAsyncSocketLoggingEnabled

// Logging Enabled - See log level below

// Logging uses the CocoaLumberjack framework (which is also GCD based).
// https://github.com/robbiehanson/CocoaLumberjack
// 
// It allows us to do a lot of logging without significantly slowing down the code.
#import "DDLog.h"

#define LogAsync   YES
#define LogContext GCDAsyncSocketLoggingContext

#define LogObjc(flg, frmt, ...) LOG_OBJC_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)
#define LogC(flg, frmt, ...)    LOG_C_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)

#define LogError(frmt, ...)     LogObjc(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogObjc(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogObjc(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogObjc(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogCError(frmt, ...)    LogC(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCWarn(frmt, ...)     LogC(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCInfo(frmt, ...)     LogC(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCVerbose(frmt, ...)  LogC(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogTrace()              LogObjc(LOG_FLAG_VERBOSE, @"%@: %@", THIS_FILE, THIS_METHOD)
#define LogCTrace()             LogC(LOG_FLAG_VERBOSE, @"%@: %s", THIS_FILE, __FUNCTION__)

#ifndef GCDAsyncSocketLogLevel
#define GCDAsyncSocketLogLevel LOG_LEVEL_VERBOSE
#endif

// Log levels : off, error, warn, info, verbose
static const int logLevel = GCDAsyncSocketLogLevel;

#else

// Logging Disabled

#define LogError(frmt, ...)     {}
#define LogWarn(frmt, ...)      {}
#define LogInfo(frmt, ...)      {}
#define LogVerbose(frmt, ...)   {}

#define LogCError(frmt, ...)    {}
#define LogCWarn(frmt, ...)     {}
#define LogCInfo(frmt, ...)     {}
#define LogCVerbose(frmt, ...)  {}

#define LogTrace()              {}
#define LogCTrace(frmt, ...)    {}

#endif

/**
 * Seeing a return statements within an inner block
 * can sometimes be mistaken for a return point of the enclosing method.
 * This makes inline blocks a bit easier to read.
**/
#define return_from_block  return

/**
 * A socket file descriptor is really just an integer.
 * It represents the index of the socket within the kernel.
 * This makes invalid file descriptor comparisons easier to read.
**/
#define SOCKET_NULL -1


NSString *const GCDAsyncSocketException = @"GCDAsyncSocketException";
NSString *const GCDAsyncSocketErrorDomain = @"GCDAsyncSocketErrorDomain";

NSString *const GCDAsyncSocketQueueName = @"GCDAsyncSocket";
NSString *const GCDAsyncSocketThreadName = @"GCDAsyncSocket-CFStream";

NSString *const GCDAsyncSocketManuallyEvaluateTrust = @"GCDAsyncSocketManuallyEvaluateTrust";
#if TARGET_OS_IPHONE
NSString *const GCDAsyncSocketUseCFStreamForTLS = @"GCDAsyncSocketUseCFStreamForTLS";
#endif
NSString *const GCDAsyncSocketSSLPeerID = @"GCDAsyncSocketSSLPeerID";
NSString *const GCDAsyncSocketSSLProtocolVersionMin = @"GCDAsyncSocketSSLProtocolVersionMin";
NSString *const GCDAsyncSocketSSLProtocolVersionMax = @"GCDAsyncSocketSSLProtocolVersionMax";
NSString *const GCDAsyncSocketSSLSessionOptionFalseStart = @"GCDAsyncSocketSSLSessionOptionFalseStart";
NSString *const GCDAsyncSocketSSLSessionOptionSendOneByteRecord = @"GCDAsyncSocketSSLSessionOptionSendOneByteRecord";
NSString *const GCDAsyncSocketSSLCipherSuites = @"GCDAsyncSocketSSLCipherSuites";
#if !TARGET_OS_IPHONE
NSString *const GCDAsyncSocketSSLDiffieHellmanParameters = @"GCDAsyncSocketSSLDiffieHellmanParameters";
#endif

enum GCDAsyncSocketFlags
{
	kSocketStarted                 = 1 <<  0,  // If set, socket has been started (accepting/connecting)
	kConnected                     = 1 <<  1,  // If set, the socket is connected
	kForbidReadsWrites             = 1 <<  2,  // If set, no new reads or writes are allowed
	kReadsPaused                   = 1 <<  3,  // If set, reads are paused due to possible timeout
	kWritesPaused                  = 1 <<  4,  // If set, writes are paused due to possible timeout
	kDisconnectAfterReads          = 1 <<  5,  // If set, disconnect after no more reads are queued
	kDisconnectAfterWrites         = 1 <<  6,  // If set, disconnect after no more writes are queued
	kSocketCanAcceptBytes          = 1 <<  7,  // If set, we know socket can accept bytes. If unset, it's unknown.
	kReadSourceSuspended           = 1 <<  8,  // If set, the read source is suspended
	kWriteSourceSuspended          = 1 <<  9,  // If set, the write source is suspended
	kQueuedTLS                     = 1 << 10,  // If set, we've queued an upgrade to TLS
	kStartingReadTLS               = 1 << 11,  // If set, we're waiting for TLS negotiation to complete
	kStartingWriteTLS              = 1 << 12,  // If set, we're waiting for TLS negotiation to complete
	kSocketSecure                  = 1 << 13,  // If set, socket is using secure communication via SSL/TLS
	kSocketHasReadEOF              = 1 << 14,  // If set, we have read EOF from socket
	kReadStreamClosed              = 1 << 15,  // If set, we've read EOF plus prebuffer has been drained
	kDealloc                       = 1 << 16,  // If set, the socket is being deallocated
#if TARGET_OS_IPHONE
	kAddedStreamsToRunLoop         = 1 << 17,  // If set, CFStreams have been added to listener thread
	kUsingCFStreamForTLS           = 1 << 18,  // If set, we're forced to use CFStream instead of SecureTransport
	kSecureSocketHasBytesAvailable = 1 << 19,  // If set, CFReadStream has notified us of bytes available
#endif
};

enum GCDAsyncSocketConfig
{
	kIPv4Disabled              = 1 << 0,  // If set, IPv4 is disabled
	kIPv6Disabled              = 1 << 1,  // If set, IPv6 is disabled
	kPreferIPv6                = 1 << 2,  // If set, IPv6 is preferred over IPv4
	kAllowHalfDuplexConnection = 1 << 3,  // If set, the socket will stay open even if the read stream closes
};

#if TARGET_OS_IPHONE
  static NSThread *cfstreamThread;  // Used for CFStreams


  static uint64_t cfstreamThreadRetainCount;   // setup & teardown
  static dispatch_queue_t cfstreamThreadSetupQueue; // setup & teardown
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * A PreBuffer is used when there is more data available on the socket
 * than is being requested by current read request.
 * In this case we slurp up all data from the socket (to minimize sys calls),
 * and store additional yet unread data in a "prebuffer".
 * 
 * The prebuffer is entirely drained before we read from the socket again.
 * In other words, a large chunk of data is written is written to the prebuffer.
 * The prebuffer is then drained via a series of one or more reads (for subsequent read request(s)).
 * 
 * A ring buffer was once used for this purpose.
 * But a ring buffer takes up twice as much memory as needed (double the size for mirroring).
 * In fact, it generally takes up more than twice the needed size as everything has to be rounded up to vm_page_size.
 * And since the prebuffer is always completely drained after being written to, a full ring buffer isn't needed.
 * 
 * The current design is very simple and straight-forward, while also keeping memory requirements lower.
**/

@interface GCDAsyncSocketPreBuffer : NSObject
{
	uint8_t *preBuffer;
	size_t preBufferSize;
	
	uint8_t *readPointer;
	uint8_t *writePointer;
}

- (id)initWithCapacity:(size_t)numBytes;

- (void)ensureCapacityForWrite:(size_t)numBytes;

- (size_t)availableBytes;
- (uint8_t *)readBuffer;

- (void)getReadBuffer:(uint8_t **)bufferPtr availableBytes:(size_t *)availableBytesPtr;

- (size_t)availableSpace;
- (uint8_t *)writeBuffer;

- (void)getWriteBuffer:(uint8_t **)bufferPtr availableSpace:(size_t *)availableSpacePtr;

- (void)didRead:(size_t)bytesRead;
- (void)didWrite:(size_t)bytesWritten;

- (void)reset;

@end

@implementation GCDAsyncSocketPreBuffer

- (id)initWithCapacity:(size_t)numBytes
{
	if ((self = [super init]))
	{
		preBufferSize = numBytes;
		preBuffer = malloc(preBufferSize);
		
		readPointer = preBuffer;
		writePointer = preBuffer;
	}
	return self;
}

- (void)dealloc
{
	if (preBuffer)
		free(preBuffer);
}

- (void)ensureCapacityForWrite:(size_t)numBytes
{
	size_t availableSpace = [self availableSpace];
	
	if (numBytes > availableSpace)
	{
		size_t additionalBytes = numBytes - availableSpace;
		
		size_t newPreBufferSize = preBufferSize + additionalBytes;
		uint8_t *newPreBuffer = realloc(preBuffer, newPreBufferSize);
		
		size_t readPointerOffset = readPointer - preBuffer;
		size_t writePointerOffset = writePointer - preBuffer;
		
		preBuffer = newPreBuffer;
		preBufferSize = newPreBufferSize;
		
		readPointer = preBuffer + readPointerOffset;
		writePointer = preBuffer + writePointerOffset;
	}
}

- (size_t)availableBytes
{
	return writePointer - readPointer;
}

- (uint8_t *)readBuffer
{
	return readPointer;
}

- (void)getReadBuffer:(uint8_t **)bufferPtr availableBytes:(size_t *)availableBytesPtr
{
	if (bufferPtr) *bufferPtr = readPointer;
	if (availableBytesPtr) *availableBytesPtr = [self availableBytes];
}

- (void)didRead:(size_t)bytesRead
{
	readPointer += bytesRead;
	
	if (readPointer == writePointer)
	{
		// The prebuffer has been drained. Reset pointers.
		readPointer  = preBuffer;
		writePointer = preBuffer;
	}
}

- (size_t)availableSpace
{
	return preBufferSize - (writePointer - preBuffer);
}

- (uint8_t *)writeBuffer
{
	return writePointer;
}

- (void)getWriteBuffer:(uint8_t **)bufferPtr availableSpace:(size_t *)availableSpacePtr
{
	if (bufferPtr) *bufferPtr = writePointer;
	if (availableSpacePtr) *availableSpacePtr = [self availableSpace];
}

- (void)didWrite:(size_t)bytesWritten
{
	writePointer += bytesWritten;
}

- (void)reset
{
	readPointer  = preBuffer;
	writePointer = preBuffer;
}

@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncReadPacket encompasses the instructions for any given read.
 * The content of a read packet allows the code to determine if we're:
 *  - reading to a certain length
 *  - reading to a certain separator
 *  - or simply reading the first chunk of available data
**/
@interface GCDAsyncReadPacket : NSObject
{
  @public
    //当前包的数据（容器，有可能为空）
	NSMutableData *buffer;
    //开始偏移（数据在容器中开始写的偏移）
	NSUInteger startOffset;
    //已读字节数（已经写了个字节数）
	NSUInteger bytesDone;
    //想要读取数据的最大长度（有可能没有）
	NSUInteger maxLength;
    //超时时长
	NSTimeInterval timeout;
    //当前需要读取的总长度（这一次 read 读取的长度，不一定，如果没有则可用 maxLength）
	NSUInteger readLength;
    //包的边界标识数据（可能没有）
	NSData *term;
    //判断 buffer 的拥有者是不是这个类，还是用户
    //跟初始化传不传一个 buffer 进来有关，如果传了，则拥有者为用户 NO, 否则为 YES
	BOOL bufferOwner;
    //原始传过来的 data长度
	NSUInteger originalBufferLength;
    //数据包的 tag
	long tag;
}

//初始化
- (id)initWithData:(NSMutableData *)d
       startOffset:(NSUInteger)s
         maxLength:(NSUInteger)m
           timeout:(NSTimeInterval)t
        readLength:(NSUInteger)l
        terminator:(NSData *)e
               tag:(long)i;

//确保容器大小给多余的长度
- (void)ensureCapacityForAdditionalDataOfLength:(NSUInteger)bytesToRead;

//预期中读的大小，决定是否走 preBuffer
- (NSUInteger)optimalReadLengthWithDefault:(NSUInteger)defaultValue shouldPreBuffer:(BOOL *)shouldPreBufferPtr;

//读取指定长度的数据
- (NSUInteger)readLengthForNonTermWithHint:(NSUInteger)bytesAvailable;
//上两个方法的综合
- (NSUInteger)readLengthForTermWithHint:(NSUInteger)bytesAvailable shouldPreBuffer:(BOOL *)shouldPreBufferPtr;
//根据一个终结符去读数据，直到读到终结的位置或者最大数据的位置，返回值为该包的确定长度
- (NSUInteger)readLengthForTermWithPreBuffer:(GCDAsyncSocketPreBuffer *)preBuffer found:(BOOL *)foundPtr;
//查找终结符， 在 prebuffer 之后，返回值为该包的确定长度
- (NSInteger)searchForTermAfterPreBuffering:(ssize_t)numBytes;

@end

@implementation GCDAsyncReadPacket

- (id)initWithData:(NSMutableData *)d
       startOffset:(NSUInteger)s
         maxLength:(NSUInteger)m
           timeout:(NSTimeInterval)t
        readLength:(NSUInteger)l
        terminator:(NSData *)e
               tag:(long)i
{
	if((self = [super init]))
	{
		bytesDone = 0;
		maxLength = m;
		timeout = t;
		readLength = l;
		term = [e copy];
		tag = i;
		
		if (d)
		{
			buffer = d;
			startOffset = s;
			bufferOwner = NO;
			originalBufferLength = [d length];
		}
		else
		{
			if (readLength > 0)
				buffer = [[NSMutableData alloc] initWithLength:readLength];
			else
				buffer = [[NSMutableData alloc] initWithLength:0];
			
			startOffset = 0;
			bufferOwner = YES;
			originalBufferLength = 0;
		}
	}
	return self;
}

/**
 * Increases the length of the buffer (if needed) to ensure a read of the given size will fit.
**/
- (void)ensureCapacityForAdditionalDataOfLength:(NSUInteger)bytesToRead
{
	NSUInteger buffSize = [buffer length];
	NSUInteger buffUsed = startOffset + bytesDone;
	
	NSUInteger buffSpace = buffSize - buffUsed;
	
	if (bytesToRead > buffSpace)
	{
		NSUInteger buffInc = bytesToRead - buffSpace;
		
		[buffer increaseLengthBy:buffInc];
	}
}

/**
 * This method is used when we do NOT know how much data is available to be read from the socket.
 * This method returns the default value unless it exceeds the specified readLength or maxLength.
 * 
 * Furthermore, the shouldPreBuffer decision is based upon the packet type,
 * and whether the returned value would fit in the current buffer without requiring a resize of the buffer.
**/
- (NSUInteger)optimalReadLengthWithDefault:(NSUInteger)defaultValue shouldPreBuffer:(BOOL *)shouldPreBufferPtr
{
	NSUInteger result;
	
	if (readLength > 0)
	{
		// Read a specific length of data
		
		result = MIN(defaultValue, (readLength - bytesDone));
		
		// There is no need to prebuffer since we know exactly how much data we need to read.
		// Even if the buffer isn't currently big enough to fit this amount of data,
		// it would have to be resized eventually anyway.
		
		if (shouldPreBufferPtr)
			*shouldPreBufferPtr = NO;
	}
	else
	{
		// Either reading until we find a specified terminator,
		// or we're simply reading all available data.
		// 
		// In other words, one of:
		// 
		// - readDataToData packet
		// - readDataWithTimeout packet
		
		if (maxLength > 0)
			result =  MIN(defaultValue, (maxLength - bytesDone));
		else
			result = defaultValue;
		
		// Since we don't know the size of the read in advance,
		// the shouldPreBuffer decision is based upon whether the returned value would fit
		// in the current buffer without requiring a resize of the buffer.
		// 
		// This is because, in all likelyhood, the amount read from the socket will be less than the default value.
		// Thus we should avoid over-allocating the read buffer when we can simply use the pre-buffer instead.
		
		if (shouldPreBufferPtr)
		{
			NSUInteger buffSize = [buffer length];
			NSUInteger buffUsed = startOffset + bytesDone;
			
			NSUInteger buffSpace = buffSize - buffUsed;
			
			if (buffSpace >= result)
				*shouldPreBufferPtr = NO;
			else
				*shouldPreBufferPtr = YES;
		}
	}
	
	return result;
}

/**
 * For read packets without a set terminator, returns the amount of data
 * that can be read without exceeding the readLength or maxLength.
 * 
 * The given parameter indicates the number of bytes estimated to be available on the socket,
 * which is taken into consideration during the calculation.
 * 
 * The given hint MUST be greater than zero.
**/
- (NSUInteger)readLengthForNonTermWithHint:(NSUInteger)bytesAvailable
{
	NSAssert(term == nil, @"This method does not apply to term reads");
	NSAssert(bytesAvailable > 0, @"Invalid parameter: bytesAvailable");
	
	if (readLength > 0)
	{
		// Read a specific length of data
		
		return MIN(bytesAvailable, (readLength - bytesDone));
		
		// No need to avoid resizing the buffer.
		// If the user provided their own buffer,
		// and told us to read a certain length of data that exceeds the size of the buffer,
		// then it is clear that our code will resize the buffer during the read operation.
		// 
		// This method does not actually do any resizing.
		// The resizing will happen elsewhere if needed.
	}
	else
	{
		// Read all available data
		
		NSUInteger result = bytesAvailable;
		
		if (maxLength > 0)
		{
			result = MIN(result, (maxLength - bytesDone));
		}
		
		// No need to avoid resizing the buffer.
		// If the user provided their own buffer,
		// and told us to read all available data without giving us a maxLength,
		// then it is clear that our code might resize the buffer during the read operation.
		// 
		// This method does not actually do any resizing.
		// The resizing will happen elsewhere if needed.
		
		return result;
	}
}

/**
 * For read packets with a set terminator, returns the amount of data
 * that can be read without exceeding the maxLength.
 * 
 * The given parameter indicates the number of bytes estimated to be available on the socket,
 * which is taken into consideration during the calculation.
 * 
 * To optimize memory allocations, mem copies, and mem moves
 * the shouldPreBuffer boolean value will indicate if the data should be read into a prebuffer first,
 * or if the data can be read directly into the read packet's buffer.
**/
- (NSUInteger)readLengthForTermWithHint:(NSUInteger)bytesAvailable shouldPreBuffer:(BOOL *)shouldPreBufferPtr
{
	NSAssert(term != nil, @"This method does not apply to non-term reads");
	NSAssert(bytesAvailable > 0, @"Invalid parameter: bytesAvailable");
	
	
	NSUInteger result = bytesAvailable;
	
	if (maxLength > 0)
	{
		result = MIN(result, (maxLength - bytesDone));
	}
	
	// Should the data be read into the read packet's buffer, or into a pre-buffer first?
	// 
	// One would imagine the preferred option is the faster one.
	// So which one is faster?
	// 
	// Reading directly into the packet's buffer requires:
	// 1. Possibly resizing packet buffer (malloc/realloc)
	// 2. Filling buffer (read)
	// 3. Searching for term (memcmp)
	// 4. Possibly copying overflow into prebuffer (malloc/realloc, memcpy)
	// 
	// Reading into prebuffer first:
	// 1. Possibly resizing prebuffer (malloc/realloc)
	// 2. Filling buffer (read)
	// 3. Searching for term (memcmp)
	// 4. Copying underflow into packet buffer (malloc/realloc, memcpy)
	// 5. Removing underflow from prebuffer (memmove)
	// 
	// Comparing the performance of the two we can see that reading
	// data into the prebuffer first is slower due to the extra memove.
	// 
	// However:
	// The implementation of NSMutableData is open source via core foundation's CFMutableData.
	// Decreasing the length of a mutable data object doesn't cause a realloc.
	// In other words, the capacity of a mutable data object can grow, but doesn't shrink.
	// 
	// This means the prebuffer will rarely need a realloc.
	// The packet buffer, on the other hand, may often need a realloc.
	// This is especially true if we are the buffer owner.
	// Furthermore, if we are constantly realloc'ing the packet buffer,
	// and then moving the overflow into the prebuffer,
	// then we're consistently over-allocating memory for each term read.
	// And now we get into a bit of a tradeoff between speed and memory utilization.
	// 
	// The end result is that the two perform very similarly.
	// And we can answer the original question very simply by another means.
	// 
	// If we can read all the data directly into the packet's buffer without resizing it first,
	// then we do so. Otherwise we use the prebuffer.
	
	if (shouldPreBufferPtr)
	{
		NSUInteger buffSize = [buffer length];
		NSUInteger buffUsed = startOffset + bytesDone;
		
		if ((buffSize - buffUsed) >= result)
			*shouldPreBufferPtr = NO;
		else
			*shouldPreBufferPtr = YES;
	}
	
	return result;
}

/**
 * For read packets with a set terminator,
 * returns the amount of data that can be read from the given preBuffer,
 * without going over a terminator or the maxLength.
 * 
 * It is assumed the terminator has not already been read.
**/
- (NSUInteger)readLengthForTermWithPreBuffer:(GCDAsyncSocketPreBuffer *)preBuffer found:(BOOL *)foundPtr
{
	NSAssert(term != nil, @"This method does not apply to non-term reads");
	NSAssert([preBuffer availableBytes] > 0, @"Invoked with empty pre buffer!");
	
	// We know that the terminator, as a whole, doesn't exist in our own buffer.
	// But it is possible that a _portion_ of it exists in our buffer.
	// So we're going to look for the terminator starting with a portion of our own buffer.
	// 
	// Example:
	// 
	// term length      = 3 bytes
	// bytesDone        = 5 bytes
	// preBuffer length = 5 bytes
	// 
	// If we append the preBuffer to our buffer,
	// it would look like this:
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------------------
	// 
	// So we start our search here:
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// -------^-^-^---------
	// 
	// And move forwards...
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------^-^-^-------
	// 
	// Until we find the terminator or reach the end.
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------------^-^-^-
	
	BOOL found = NO;
	
	NSUInteger termLength = [term length];
	NSUInteger preBufferLength = [preBuffer availableBytes];
	
	if ((bytesDone + preBufferLength) < termLength)
	{
		// Not enough data for a full term sequence yet
		return preBufferLength;
	}
	
	NSUInteger maxPreBufferLength;
	if (maxLength > 0) {
		maxPreBufferLength = MIN(preBufferLength, (maxLength - bytesDone));
		
		// Note: maxLength >= termLength
	}
	else {
		maxPreBufferLength = preBufferLength;
	}
	
	uint8_t seq[termLength];
	const void *termBuf = [term bytes];
	
	NSUInteger bufLen = MIN(bytesDone, (termLength - 1));
	uint8_t *buf = (uint8_t *)[buffer mutableBytes] + startOffset + bytesDone - bufLen;
	
	NSUInteger preLen = termLength - bufLen;
	const uint8_t *pre = [preBuffer readBuffer];
	
	NSUInteger loopCount = bufLen + maxPreBufferLength - termLength + 1; // Plus one. See example above.
	
	NSUInteger result = maxPreBufferLength;
	
	NSUInteger i;
	for (i = 0; i < loopCount; i++)
	{
		if (bufLen > 0)
		{
			// Combining bytes from buffer and preBuffer
			
			memcpy(seq, buf, bufLen);
			memcpy(seq + bufLen, pre, preLen);
			
			if (memcmp(seq, termBuf, termLength) == 0)
			{
				result = preLen;
				found = YES;
				break;
			}
			
			buf++;
			bufLen--;
			preLen++;
		}
		else
		{
			// Comparing directly from preBuffer
			
			if (memcmp(pre, termBuf, termLength) == 0)
			{
				NSUInteger preOffset = pre - [preBuffer readBuffer]; // pointer arithmetic
				
				result = preOffset + termLength;
				found = YES;
				break;
			}
			
			pre++;
		}
	}
	
	// There is no need to avoid resizing the buffer in this particular situation.
	
	if (foundPtr) *foundPtr = found;
	return result;
}

/**
 * For read packets with a set terminator, scans the packet buffer for the term.
 * It is assumed the terminator had not been fully read prior to the new bytes.
 * 
 * If the term is found, the number of excess bytes after the term are returned.
 * If the term is not found, this method will return -1.
 * 
 * Note: A return value of zero means the term was found at the very end.
 * 
 * Prerequisites:
 * The given number of bytes have been added to the end of our buffer.
 * Our bytesDone variable has NOT been changed due to the prebuffered bytes.
**/
- (NSInteger)searchForTermAfterPreBuffering:(ssize_t)numBytes
{
	NSAssert(term != nil, @"This method does not apply to non-term reads");
	
	// The implementation of this method is very similar to the above method.
	// See the above method for a discussion of the algorithm used here.
	
	uint8_t *buff = [buffer mutableBytes];
	NSUInteger buffLength = bytesDone + numBytes;
	
	const void *termBuff = [term bytes];
	NSUInteger termLength = [term length];
	
	// Note: We are dealing with unsigned integers,
	// so make sure the math doesn't go below zero.
	
	NSUInteger i = ((buffLength - numBytes) >= termLength) ? (buffLength - numBytes - termLength + 1) : 0;
	
	while (i + termLength <= buffLength)
	{
		uint8_t *subBuffer = buff + startOffset + i;
		
		if (memcmp(subBuffer, termBuff, termLength) == 0)
		{
			return buffLength - (i + termLength);
		}
		
		i++;
	}
	
	return -1;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncWritePacket encompasses the instructions for any given write.
**/
@interface GCDAsyncWritePacket : NSObject
{
  @public
	NSData *buffer;
	NSUInteger bytesDone;
	long tag;
	NSTimeInterval timeout;
}
- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i;
@end

@implementation GCDAsyncWritePacket

- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i
{
	if((self = [super init]))
	{
		buffer = d; // Retain not copy. For performance as documented in header file.
		bytesDone = 0;
		timeout = t;
		tag = i;
	}
	return self;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncSpecialPacket encompasses special instructions for interruptions in the read/write queues.
 * This class my be altered to support more than just TLS in the future.
**/
@interface GCDAsyncSpecialPacket : NSObject
{
  @public
	NSDictionary *tlsSettings;
}
- (id)initWithTLSSettings:(NSDictionary *)settings;
@end

@implementation GCDAsyncSpecialPacket

- (id)initWithTLSSettings:(NSDictionary *)settings
{
	if((self = [super init]))
	{
		tlsSettings = [settings copy];
	}
	return self;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@implementation GCDAsyncSocket
{
    //flags 当前正在做操作的标识符
	uint32_t flags;
	uint16_t config;
	
    //代理
	__weak id<GCDAsyncSocketDelegate> delegate;
    //代理回调 queue
	dispatch_queue_t delegateQueue;
	
    //本地 IPV4Socket
	int socket4FD;
    //本地 IPV6Socket
	int socket6FD;
    //unix 域的套接字
	int socketUN;
    //unix 域 服务器 url
	NSURL *socketUrl;
    //状态 index
	int stateIndex;
    
    //本机的 IPV4 地址
	NSData * connectInterface4;
    //本机的 IPV6 地址
	NSData * connectInterface6;
    //本机 unix地址
	NSData * connectInterfaceUN;
	
    //这个类的对 Socket 的操作都在这个 queue 中，串行
	dispatch_queue_t socketQueue;
	
	dispatch_source_t accept4Source;
	dispatch_source_t accept6Source;
	dispatch_source_t acceptUNSource;
    
    //连接 timer, GCD 定时器
	dispatch_source_t connectTimer;
	dispatch_source_t readSource;
	dispatch_source_t writeSource;
	dispatch_source_t readTimer;
	dispatch_source_t writeTimer;
	
    //读取数据包数组，类似 queue,最大限制为5个包
	NSMutableArray *readQueue;
	NSMutableArray *writeQueue;
	
    //当前这次读取的数据任务包
	GCDAsyncReadPacket *currentRead;
	GCDAsyncWritePacket *currentWrite;
	
    //当前 socket 未获取完的数据大小
	unsigned long socketFDBytesAvailable;
	
    //全局公用的提前缓冲区
	GCDAsyncSocketPreBuffer *preBuffer;
		
#if TARGET_OS_IPHONE
	CFStreamClientContext streamContext;
    //读的数据流
	CFReadStreamRef readStream;
    //写的数据流
	CFWriteStreamRef writeStream;
#endif
    //SSL 上下文， 用来做 SSL 认证
	SSLContextRef sslContext;
    //全局公用的 SSL的提前缓冲区
	GCDAsyncSocketPreBuffer *sslPreBuffer;
	size_t sslWriteCachedLength;
    
    //记录 SSL 读取数据错误
	OSStatus sslErrCode;
    //记录 SSL握手错误
    OSStatus lastSSLHandshakeError;
	
    //socket 队列的标识 key
	void *IsOnSocketQueueOrTargetQueueKey;
	
	id userData;
    //连接备选服务端地址的延时（另一个 IPV4或 IPV6）
    NSTimeInterval alternateAddressDelay;
}

- (id)init
{
	return [self initWithDelegate:nil delegateQueue:NULL socketQueue:NULL];
}

- (id)initWithSocketQueue:(dispatch_queue_t)sq
{
	return [self initWithDelegate:nil delegateQueue:NULL socketQueue:sq];
}

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq
{
	return [self initWithDelegate:aDelegate delegateQueue:dq socketQueue:NULL];
}

- (id)initWithDelegate:(id<GCDAsyncSocketDelegate>)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq
{
	if((self = [super init]))
	{
		delegate = aDelegate;
		delegateQueue = dq;
		
        //这个宏是 sdk6.0之后才有的，如果是之前的，则OS_OBJECT_USE_OBJC为0， !0即执行 if 语句
        //对6.0的适配，如果是6.0以下的，则去 retain,release, 6.0之后 ARC 也管理了 GCD
		#if !OS_OBJECT_USE_OBJC
		if (dq) dispatch_retain(dq);
		#endif
		
        //创建 socket,  先都置为-1
        //本机的 ipv4
		socket4FD = SOCKET_NULL;
        //ipv6
		socket6FD = SOCKET_NULL;
        //应该是 UnixSocket
		socketUN = SOCKET_NULL;
        //url
		socketUrl = nil;
        //状态
		stateIndex = 0;
		
		if (sq)
		{
            //如果 socketQueue 是 global 的，则报错。断言必须是一个非并行 queue
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			
            //拿到 socketQueue
			socketQueue = sq;
            
            //iOS6之下的 retain
			#if !OS_OBJECT_USE_OBJC
			dispatch_retain(sq);
			#endif
		}
		else
		{
            //没有的话创建一个 名字为：GCDAsyncSocket, 串行
			socketQueue = dispatch_queue_create([GCDAsyncSocketQueueName UTF8String], NULL);
		}
		
		// The dispatch_queue_set_specific() and dispatch_get_specific() functions take a "void *key" parameter.
		// From the documentation:
		//
		// > Keys are only compared as pointers and are never dereferenced.
		// > Thus, you can use a pointer to a static variable for a specific subsystem or
		// > any other value that allows you to identify the value uniquely.
		//
		// We're just going to use the memory address of an ivar.
		// Specifically an ivar that is explicitly named for our purpose to make the code more readable.
		//
		// However, it feels tedious (and less readable) to include the "&" all the time:
		// dispatch_get_specific(&IsOnSocketQueueOrTargetQueueKey)
		//
		// So we're going to make it so it doesn't matter if we use the '&' or not,
		// by assigning the value of the ivar to the address of the ivar.
		// Thus: IsOnSocketQueueOrTargetQueueKey == &IsOnSocketQueueOrTargetQueueKey;
		
        //比如原来为  0X123 -> NULL  变成  0X222 -> 0X123 -> NULL
        //自己的指针等于自己原来的指针，成二级指针了，看了注释是为了以后省略&， 让代码更可读
		IsOnSocketQueueOrTargetQueueKey = &IsOnSocketQueueOrTargetQueueKey;
		
		void *nonNullUnusedPointer = (__bridge void *)self;
        
        //dispatch_queue_set_specific 给当前队里加一个标识 dispatch_get_specific 当前线程取出这个标识，判断是不是在这个队列
        //这个 key 的值其实就是一个一级指正的地址，第三个参数把自己传过去，上下文对象？ 第4个参数，为销毁的时候调用，可以指定一个函数
		dispatch_queue_set_specific(socketQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
		//读的数组  限制为5
		readQueue = [[NSMutableArray alloc] initWithCapacity:5];
		currentRead = nil;
		
        //写的数组 限制为5
		writeQueue = [[NSMutableArray alloc] initWithCapacity:5];
		currentWrite = nil;
		
        //设置大小为4kb
		preBuffer = [[GCDAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
        
        //交替地址延时  wef
        alternateAddressDelay = 0.3;
	}
	return self;
}

- (void)dealloc
{
	LogInfo(@"%@ - %@ (start)", THIS_METHOD, self);
	
	// Set dealloc flag.
	// This is used by closeWithError to ensure we don't accidentally retain ourself.
	flags |= kDealloc;
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		[self closeWithError:nil];
	}
	else
	{
		dispatch_sync(socketQueue, ^{
			[self closeWithError:nil];
		});
	}
	
	delegate = nil;
	
	#if !OS_OBJECT_USE_OBJC
	if (delegateQueue) dispatch_release(delegateQueue);
	#endif
	delegateQueue = NULL;
	
	#if !OS_OBJECT_USE_OBJC
	if (socketQueue) dispatch_release(socketQueue);
	#endif
	socketQueue = NULL;
	
	LogInfo(@"%@ - %@ (finish)", THIS_METHOD, self);
}

#pragma mark -

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD socketQueue:(nullable dispatch_queue_t)sq error:(NSError**)error {
  return [self socketFromConnectedSocketFD:socketFD delegate:nil delegateQueue:NULL socketQueue:sq error:error];
}

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<GCDAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq error:(NSError**)error {
  return [self socketFromConnectedSocketFD:socketFD delegate:aDelegate delegateQueue:dq socketQueue:NULL error:error];
}

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<GCDAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq socketQueue:(nullable dispatch_queue_t)sq error:(NSError* __autoreleasing *)error
{
  __block BOOL errorOccured = NO;
  
  GCDAsyncSocket *socket = [[[self class] alloc] initWithDelegate:aDelegate delegateQueue:dq socketQueue:sq];
  
  dispatch_sync(socket->socketQueue, ^{ @autoreleasepool {
    struct sockaddr addr;
    socklen_t addr_size = sizeof(struct sockaddr);
    int retVal = getpeername(socketFD, (struct sockaddr *)&addr, &addr_size);
    if (retVal)
    {
      NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketOtherError",
                                                           @"GCDAsyncSocket", [NSBundle mainBundle],
                                                           @"Attempt to create socket from socket FD failed. getpeername() failed", nil);
      
      NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];

      errorOccured = YES;
      if (error)
        *error = [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketOtherError userInfo:userInfo];
      return;
    }
    
    if (addr.sa_family == AF_INET)
    {
      socket->socket4FD = socketFD;
    }
    else if (addr.sa_family == AF_INET6)
    {
      socket->socket6FD = socketFD;
    }
    else
    {
      NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketOtherError",
                                                           @"GCDAsyncSocket", [NSBundle mainBundle],
                                                           @"Attempt to create socket from socket FD failed. socket FD is neither IPv4 nor IPv6", nil);
      
      NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
      
      errorOccured = YES;
      if (error)
        *error = [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketOtherError userInfo:userInfo];
      return;
    }
    
    socket->flags = kSocketStarted;
    [socket didConnect:socket->stateIndex];
  }});
  
  return errorOccured? nil: socket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Configuration
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (id)delegate
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return delegate;
	}
	else
	{
		__block id result;
		
		dispatch_sync(socketQueue, ^{
			result = delegate;
		});
		
		return result;
	}
}

- (void)setDelegate:(id)newDelegate synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		delegate = newDelegate;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegate:(id)newDelegate
{
	[self setDelegate:newDelegate synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate
{
	[self setDelegate:newDelegate synchronously:YES];
}

- (dispatch_queue_t)delegateQueue
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return delegateQueue;
	}
	else
	{
		__block dispatch_queue_t result;
		
		dispatch_sync(socketQueue, ^{
			result = delegateQueue;
		});
		
		return result;
	}
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		
		#if !OS_OBJECT_USE_OBJC
		if (delegateQueue) dispatch_release(delegateQueue);
		if (newDelegateQueue) dispatch_retain(newDelegateQueue);
		#endif
		
		delegateQueue = newDelegateQueue;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegateQueue:newDelegateQueue synchronously:YES];
}

- (void)getDelegate:(id<GCDAsyncSocketDelegate> *)delegatePtr delegateQueue:(dispatch_queue_t *)delegateQueuePtr
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (delegatePtr) *delegatePtr = delegate;
		if (delegateQueuePtr) *delegateQueuePtr = delegateQueue;
	}
	else
	{
		__block id dPtr = NULL;
		__block dispatch_queue_t dqPtr = NULL;
		
		dispatch_sync(socketQueue, ^{
			dPtr = delegate;
			dqPtr = delegateQueue;
		});
		
		if (delegatePtr) *delegatePtr = dPtr;
		if (delegateQueuePtr) *delegateQueuePtr = dqPtr;
	}
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		
		delegate = newDelegate;
		
		#if !OS_OBJECT_USE_OBJC
		if (delegateQueue) dispatch_release(delegateQueue);
		if (newDelegateQueue) dispatch_retain(newDelegateQueue);
		#endif
		
		delegateQueue = newDelegateQueue;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:YES];
}

- (BOOL)isIPv4Enabled
{
	// Note: YES means kIPv4Disabled is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kIPv4Disabled) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kIPv4Disabled) == 0);
		});
		
		return result;
	}
}

- (void)setIPv4Enabled:(BOOL)flag
{
	// Note: YES means kIPv4Disabled is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kIPv4Disabled;
		else
			config |= kIPv4Disabled;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

- (BOOL)isIPv6Enabled
{
	// Note: YES means kIPv6Disabled is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kIPv6Disabled) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kIPv6Disabled) == 0);
		});
		
		return result;
	}
}

- (void)setIPv6Enabled:(BOOL)flag
{
	// Note: YES means kIPv6Disabled is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kIPv6Disabled;
		else
			config |= kIPv6Disabled;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

- (BOOL)isIPv4PreferredOverIPv6
{
	// Note: YES means kPreferIPv6 is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kPreferIPv6) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kPreferIPv6) == 0);
		});
		
		return result;
	}
}

- (void)setIPv4PreferredOverIPv6:(BOOL)flag
{
	// Note: YES means kPreferIPv6 is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kPreferIPv6;
		else
			config |= kPreferIPv6;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

- (NSTimeInterval) alternateAddressDelay {
    __block NSTimeInterval delay;
    dispatch_block_t block = ^{
        delay = alternateAddressDelay;
    };
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    return delay;
}

- (void) setAlternateAddressDelay:(NSTimeInterval)delay {
    dispatch_block_t block = ^{
        alternateAddressDelay = delay;
    };
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

- (id)userData
{
	__block id result = nil;
	
	dispatch_block_t block = ^{
		
		result = userData;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (void)setUserData:(id)arbitraryUserData
{
	dispatch_block_t block = ^{
		
		if (userData != arbitraryUserData)
		{
			userData = arbitraryUserData;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Accepting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//监听端口起点
- (BOOL)acceptOnPort:(uint16_t)port error:(NSError **)errPtr
{
	return [self acceptOnInterface:nil port:port error:errPtr];
}

- (BOOL)acceptOnInterface:(NSString *)inInterface port:(uint16_t)port error:(NSError **)errPtr
{
	LogTrace();
	
	// Just in-case interface parameter is immutable.
    //防止参数被修改
	NSString *interface = [inInterface copy];
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	// CreateSocket Block
	// This block will be invoked within the dispatch block below.
	
    //创建 socket 的 block
	int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
		
        //创建 tcp 的 socket
		int socketFD = socket(domain, SOCK_STREAM, 0);
		
        //一系列错误判断
		if (socketFD == SOCKET_NULL)
		{
			NSString *reason = @"Error in socket() function";
			err = [self errnoErrorWithReason:reason];
			
			return SOCKET_NULL;
		}
		
		int status;
		
		// Set socket options
		
		status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
		if (status == -1)
		{
			NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		int reuseOn = 1;
		status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
		if (status == -1)
		{
			NSString *reason = @"Error enabling address reuse (setsockopt)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Bind socket
		//用本地地址去绑定
		status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
		if (status == -1)
		{
			NSString *reason = @"Error in bind() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Listen
		//监听这个 socket
        //第二个参数是这个端口下维护的 socket 请求队列，最多容纳的用户请求数
		status = listen(socketFD, 1024);
		if (status == -1)
		{
			NSString *reason = @"Error in listen() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		return socketFD;
	};
	
	// Create dispatch block and run on socketQueue
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
        //一系列的错误判断
		if (delegate == nil) // Must have delegate set
		{
			NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (delegateQueue == NULL) // Must have delegate queue set
		{
			NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
        //判断 ipv4 ipv6是否支持
		BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
		BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
		
		if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
		{
			NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (![self isDisconnected]) // Must be disconnected
		{
			NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		// Clear queues (spurious read/write requests post disconnect)
		[readQueue removeAllObjects];
		[writeQueue removeAllObjects];
		
		// Resolve interface from description
		
		NSMutableData *interface4 = nil;
		NSMutableData *interface6 = nil;
		
        //得到本机的 ipv4  ipv6地址
		[self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:port];
		
        
        //判断可以用 ipv4 ipv6的请求
		if ((interface4 == nil) && (interface6 == nil))
		{
			NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv4Disabled && (interface6 == nil))
		{
			NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv6Disabled && (interface4 == nil))
		{
			NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		BOOL enableIPv4 = !isIPv4Disabled && (interface4 != nil);
		BOOL enableIPv6 = !isIPv6Disabled && (interface6 != nil);
		
		// Create sockets, configure, bind, and listen
		
        
		if (enableIPv4)
		{
			LogVerbose(@"Creating IPv4 socket");
			socket4FD = createSocket(AF_INET, interface4);
			
			if (socket4FD == SOCKET_NULL)
			{
				return_from_block;
			}
		}
		
		if (enableIPv6)
		{
			LogVerbose(@"Creating IPv6 socket");
			
			if (enableIPv4 && (port == 0))
			{
				// No specific port was specified, so we allowed the OS to pick an available port for us.
				// Now we need to make sure the IPv6 socket listens on the same port as the IPv4 socket.
				
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)[interface6 mutableBytes];
				addr6->sin6_port = htons([self localPort4]);
			}
			
			socket6FD = createSocket(AF_INET6, interface6);
			
			if (socket6FD == SOCKET_NULL)
			{
				if (socket4FD != SOCKET_NULL)
				{
					LogVerbose(@"close(socket4FD)");
					close(socket4FD);
				}
				
				return_from_block;
			}
		}
		
		// Create accept sources
		
        //创建接受连接被触发的 sources
		if (enableIPv4)
		{
            //接受连接的 souce
			accept4Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socket4FD, 0, socketQueue);
			
			int socketFD = socket4FD;
			dispatch_source_t acceptSource = accept4Source;
			
			__weak GCDAsyncSocket *weakSelf = self;
			
            //时间句柄
			dispatch_source_set_event_handler(accept4Source, ^{ @autoreleasepool {
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf == nil) return_from_block;
				
				LogVerbose(@"event4Block");
				//拿到数据 连接数
				unsigned long i = 0;
				unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
				
				LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
				//循环去接受这些 socket 的事件（一次触发可能有多个连接）
				while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
				
			#pragma clang diagnostic pop
			}});
			
			
            //取消句柄
			dispatch_source_set_cancel_handler(accept4Source, ^{
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				#if !OS_OBJECT_USE_OBJC
				LogVerbose(@"dispatch_release(accept4Source)");
				dispatch_release(acceptSource);
				#endif
				
                //关闭 socket
				LogVerbose(@"close(socket4FD)");
				close(socketFD);
			
			#pragma clang diagnostic pop
			});
			
            //开启 source
			LogVerbose(@"dispatch_resume(accept4Source)");
			dispatch_resume(accept4Source);
		}
		
		if (enableIPv6)
		{
			accept6Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socket6FD, 0, socketQueue);
			
			int socketFD = socket6FD;
			dispatch_source_t acceptSource = accept6Source;
			
			__weak GCDAsyncSocket *weakSelf = self;
			
			dispatch_source_set_event_handler(accept6Source, ^{ @autoreleasepool {
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf == nil) return_from_block;
				
				LogVerbose(@"event6Block");
				
				unsigned long i = 0;
				unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
				
				LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
				
				while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
				
			#pragma clang diagnostic pop
			}});
			
			dispatch_source_set_cancel_handler(accept6Source, ^{
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				#if !OS_OBJECT_USE_OBJC
				LogVerbose(@"dispatch_release(accept6Source)");
				dispatch_release(acceptSource);
				#endif
				
				LogVerbose(@"close(socket6FD)");
				close(socketFD);
				
			#pragma clang diagnostic pop
			});
			
			LogVerbose(@"dispatch_resume(accept6Source)");
			dispatch_resume(accept6Source);
		}
		
		flags |= kSocketStarted;
		
		result = YES;
	}};
	
    
    //在 socketQueue 中同步做这些初始化
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
    //错误判断
	if (result == NO)
	{
		LogInfo(@"Error in accept: %@", err);
		
		if (errPtr)
			*errPtr = err;
	}
	
    //返回结果
	return result;
}

- (BOOL)acceptOnUrl:(NSURL *)url error:(NSError **)errPtr;
{
	LogTrace();
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	// CreateSocket Block
	// This block will be invoked within the dispatch block below.
	
	int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
		
		int socketFD = socket(domain, SOCK_STREAM, 0);
		
		if (socketFD == SOCKET_NULL)
		{
			NSString *reason = @"Error in socket() function";
			err = [self errnoErrorWithReason:reason];
			
			return SOCKET_NULL;
		}
		
		int status;
		
		// Set socket options
		
		status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
		if (status == -1)
		{
			NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		int reuseOn = 1;
		status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
		if (status == -1)
		{
			NSString *reason = @"Error enabling address reuse (setsockopt)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Bind socket
		
		status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
		if (status == -1)
		{
			NSString *reason = @"Error in bind() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Listen
		
		status = listen(socketFD, 1024);
		if (status == -1)
		{
			NSString *reason = @"Error in listen() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		return socketFD;
	};
	
	// Create dispatch block and run on socketQueue
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
		if (delegate == nil) // Must have delegate set
		{
			NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (delegateQueue == NULL) // Must have delegate queue set
		{
			NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (![self isDisconnected]) // Must be disconnected
		{
			NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		// Clear queues (spurious read/write requests post disconnect)
		[readQueue removeAllObjects];
		[writeQueue removeAllObjects];
		
		// Remove a previous socket
		
		NSError *error = nil;
		NSFileManager *fileManager = [NSFileManager defaultManager];
		if ([fileManager fileExistsAtPath:url.path]) {
			if (![[NSFileManager defaultManager] removeItemAtURL:url error:&error]) {
				NSString *msg = @"Could not remove previous unix domain socket at given url.";
				err = [self otherError:msg];
				
				return_from_block;
			}
		}
		
		// Resolve interface from description
		
		NSData *interface = [self getInterfaceAddressFromUrl:url];
		
		if (interface == nil)
		{
			NSString *msg = @"Invalid unix domain url. Specify a valid file url that does not exist (e.g. \"file:///tmp/socket\")";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Create sockets, configure, bind, and listen
		
		LogVerbose(@"Creating unix domain socket");
		socketUN = createSocket(AF_UNIX, interface);
		
		if (socketUN == SOCKET_NULL)
		{
			return_from_block;
		}
		
		socketUrl = url;
		
		// Create accept sources
		
		acceptUNSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socketUN, 0, socketQueue);
		
		int socketFD = socketUN;
		dispatch_source_t acceptSource = acceptUNSource;
		
		dispatch_source_set_event_handler(acceptUNSource, ^{ @autoreleasepool {
			
			LogVerbose(@"eventUNBlock");
			
			unsigned long i = 0;
			unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
			
			LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
			
			while ([self doAccept:socketFD] && (++i < numPendingConnections));
		}});
		
		dispatch_source_set_cancel_handler(acceptUNSource, ^{
			
#if NEEDS_DISPATCH_RETAIN_RELEASE
			LogVerbose(@"dispatch_release(accept4Source)");
			dispatch_release(acceptSource);
#endif
			
			LogVerbose(@"close(socket4FD)");
			close(socketFD);
		});
		
		LogVerbose(@"dispatch_resume(accept4Source)");
		dispatch_resume(acceptUNSource);
		
		flags |= kSocketStarted;
		
		result = YES;
	}};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		LogInfo(@"Error in accept: %@", err);
		
		if (errPtr)
			*errPtr = err;
	}
	
	return result;	
}

//连接接受的方法
- (BOOL)doAccept:(int)parentSocketFD
{
	LogTrace();
	
	int socketType;
	int childSocketFD;
	NSData *childSocketAddress;
	
    //IPV4
	if (parentSocketFD == socket4FD)
	{
		socketType = 0;
		
		struct sockaddr_in addr;
		socklen_t addrLen = sizeof(addr);
		
        //调用接受，得到接受的子 socket
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		//NO说明没有连接
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		//子 socket 的地址数据
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
    //一样
	else if (parentSocketFD == socket6FD)
	{
		socketType = 1;
		
		struct sockaddr_in6 addr;
		socklen_t addrLen = sizeof(addr);
		
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
    //unix domain socket 一样
	else // if (parentSocketFD == socketUN)
	{
		socketType = 2;
		
		struct sockaddr_un addr;
		socklen_t addrLen = sizeof(addr);
		
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
	
	// Enable non-blocking IO on the socket
	
	int result = fcntl(childSocketFD, F_SETFL, O_NONBLOCK);
	if (result == -1)
	{
		LogWarn(@"Error enabling non-blocking IO on accepted socket (fcntl)");
		LogVerbose(@"close(childSocketFD)");
		close(childSocketFD);
		return NO;
	}
	
	// Prevent SIGPIPE signals
	
	int nosigpipe = 1;
	setsockopt(childSocketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
	
	// Notify delegate
	
    //响应代理
	if (delegateQueue)
	{
		__strong id theDelegate = delegate;
		//代理队列中调用
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			// Query delegate for custom socket queue
			
			dispatch_queue_t childSocketQueue = NULL;
			
            //判断是否实现了为 socket 生成一个新的 socketQueue，是的话拿到新的 queue
			if ([theDelegate respondsToSelector:@selector(newSocketQueueForConnectionFromAddress:onSocket:)])
			{
				childSocketQueue = [theDelegate newSocketQueueForConnectionFromAddress:childSocketAddress
				                                                              onSocket:self];
			}
			
			// Create GCDAsyncSocket instance for accepted socket
			//新创建一个本类实例，给接受的 socket
			GCDAsyncSocket *acceptedSocket = [[[self class] alloc] initWithDelegate:theDelegate
																	  delegateQueue:delegateQueue
																		socketQueue:childSocketQueue];
			
			if (socketType == 0)
				acceptedSocket->socket4FD = childSocketFD;
			else if (socketType == 1)
				acceptedSocket->socket6FD = childSocketFD;
			else
				acceptedSocket->socketUN = childSocketFD;
			
            //标记开始 并且已经连接
			acceptedSocket->flags = (kSocketStarted | kConnected);
			
			// Setup read and write sources for accepted socket
			
            //初始化读写 source
			dispatch_async(acceptedSocket->socketQueue, ^{ @autoreleasepool {
				
				[acceptedSocket setupReadAndWriteSourcesForNewlyConnectedSocket:childSocketFD];
			}});
			
			// Notify delegate
			//判断代理是否实现了didAcceptNewSocket方法 把我们新建的 socket 返回回去
			if ([theDelegate respondsToSelector:@selector(socket:didAcceptNewSocket:)])
			{
				[theDelegate socket:self didAcceptNewSocket:acceptedSocket];
			}
			
			// Release the socket queue returned from the delegate (it was retained by acceptedSocket)
			#if !OS_OBJECT_USE_OBJC
			if (childSocketQueue) dispatch_release(childSocketQueue);
			#endif
			
			// The accepted socket should have been retained by the delegate.
			// Otherwise it gets properly released when exiting the block.
		}});
	}
	
	return YES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Connecting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * This method runs through the various checks required prior to a connection attempt.
 * It is shared between the connectToHost and connectToAddress methods.
 * 
**/
//在连接之前的接口检查，一般我们传 nil  interface 本机的 IP 端口等等
- (BOOL)preConnectWithInterface:(NSString *)interface error:(NSError **)errPtr
{
    //先断言，如果当前的 queue 不是初始化 queue，直接报错
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
    //无代理
	if (delegate == nil) // Must have delegate set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	//没有代理 queue
	if (delegateQueue == NULL) // Must have delegate queue set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	//当前不是非连接状态
	if (![self isDisconnected]) // Must be disconnected
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
	BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
	//是否都不支持
	if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
	{
		if (errPtr)
		{
			NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	//如果有 interface 本机地址
	if (interface)
	{
		NSMutableData *interface4 = nil;
		NSMutableData *interface6 = nil;
		
        //得到本机的 IPV4 IPV6地址
		[self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:0];
		
        //如果两者都为 nil
		if ((interface4 == nil) && (interface6 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		
		if (isIPv4Disabled && (interface6 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		
		if (isIPv6Disabled && (interface4 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		//如果都没问题，则赋值
		connectInterface4 = interface4;
		connectInterface6 = interface6;
	}
	
	// Clear queues (spurious read/write requests post disconnect)
    //清除 queue（假的读写请求，提交断开连接）
    //读写 Queue 清除
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	return YES;
}

- (BOOL)preConnectWithUrl:(NSURL *)url error:(NSError **)errPtr
{
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	if (delegate == nil) // Must have delegate set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	if (delegateQueue == NULL) // Must have delegate queue set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	if (![self isDisconnected]) // Must be disconnected
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	NSData *interface = [self getInterfaceAddressFromUrl:url];
	
	if (interface == nil)
	{
		if (errPtr)
		{
			NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
			*errPtr = [self badParamError:msg];
		}
		return NO;
	}
	
	connectInterfaceUN = interface;
	
	// Clear queues (spurious read/write requests post disconnect)
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	return YES;
}

//逐级调用
- (BOOL)connectToHost:(NSString*)host onPort:(uint16_t)port error:(NSError **)errPtr
{
	return [self connectToHost:host onPort:port withTimeout:-1 error:errPtr];
}

- (BOOL)connectToHost:(NSString *)host
               onPort:(uint16_t)port
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
	return [self connectToHost:host onPort:port viaInterface:nil withTimeout:timeout error:errPtr];
}

//多一个 inInterface，本机地址
- (BOOL)connectToHost:(NSString *)inHost
               onPort:(uint16_t)port
         viaInterface:(NSString *)inInterface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    //跟踪行为
	LogTrace();
	
	// Just in case immutable objects were passed
    //拿到 host,copy 防止值被修改
	NSString *host = [inHost copy];
    //interface 接口
	NSString *interface = [inInterface copy];
	
    
    //声明两个__block 的
	__block BOOL result = NO;
    //error 信息
	__block NSError *preConnectErr = nil;
	
    //gcdBlock，都包裹在自动释放池中
	dispatch_block_t block = ^{ @autoreleasepool {
		
		// Check for problems with host parameter
		
		if ([host length] == 0)
		{
			NSString *msg = @"Invalid host parameter (nil or \"\"). Should be a domain name or IP address string.";
			preConnectErr = [self badParamError:msg];
			
            //其实就是 return
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		//一个的前置的检查，如果没通过返回，这个检查里，如果 interface 有值，则会将本机的 IPV4 IPV6的 address 设置上
		if (![self preConnectWithInterface:interface error:&preConnectErr])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		//flag 做或等运算。 flags 标识为开始 Socket 连接
		flags |= kSocketStarted;
		
        
		LogVerbose(@"Dispatching DNS lookup...");
		
		// It's possible that the given host parameter is actually a NSMutableString.
        //很可能给我们的服务器的参数是一个可变的字符串
		// So we want to copy it now, within this block that will be executed synchronously.
        //所以我们需要 copy，在 Block 里同步执行
		// This way the asynchronous lookup block below doesn't have to worry about it changing.
        //这个基于 Block 的异步查找，不需要担心它被改变
		
        //copy 防止改变
		NSString *hostCpy = [host copy];
		
        //拿到状态
		int aStateIndex = stateIndex;
		__weak GCDAsyncSocket *weakSelf = self;
		
        //全局 queue
		dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        //异步执行
		dispatch_async(globalConcurrentQueue, ^{ @autoreleasepool {
            //忽视循环引用
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			//查找错误
			NSError *lookupErr = nil;
            //server 地址数组（包含 IPV4 IPV6的地址  sockaddr_in6, sockaddr_in 类型）
			NSMutableArray *addresses = [[self class] lookupHost:hostCpy port:port error:&lookupErr];
			
            //strongSelf
			__strong GCDAsyncSocket *strongSelf = weakSelf;
            //完整 Block 安全形势  在加个 if
			if (strongSelf == nil) return_from_block;
			
            //如果有错
			if (lookupErr)
			{
                //用 socketQueue
				dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
					//一些错误的处理，清空一些数据等等
					[strongSelf lookup:aStateIndex didFail:lookupErr];
				}});
			}
            //正常
			else
			{
				NSData *address4 = nil;
				NSData *address6 = nil;
				//遍历地址数组
				for (NSData *address in addresses)
				{
                    //判断address4为空，且address4为 IPV4
					if (!address4 && [[self class] isIPv4Address:address])
					{
						address4 = address;
					}
                    //判断address6非空，且address4为 IPV6
					else if (!address6 && [[self class] isIPv6Address:address])
					{
						address6 = address;
					}
				}
				
                //异步发起连接
				dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
					
					[strongSelf lookup:aStateIndex didSucceedWithAddress4:address4 address6:address6];
				}});
			}
			
		#pragma clang diagnostic pop
		}});
		
        //开始连接超时
		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	
    //socketQueue 中执行这个 block
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
        //否则同步的调起这个 queue 去执行
		dispatch_sync(socketQueue, block);
	
	//如果有错误，赋值错误
	if (errPtr) *errPtr = preConnectErr;
    //把连接是否成功的 result 返回
	return result;
}

- (BOOL)connectToAddress:(NSData *)remoteAddr error:(NSError **)errPtr
{
	return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:-1 error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)remoteAddr withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr
{
	return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:timeout error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)inRemoteAddr
            viaInterface:(NSString *)inInterface
             withTimeout:(NSTimeInterval)timeout
                   error:(NSError **)errPtr
{
	LogTrace();
	
	// Just in case immutable objects were passed
	NSData *remoteAddr = [inRemoteAddr copy];
	NSString *interface = [inInterface copy];
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
		// Check for problems with remoteAddr parameter
		
		NSData *address4 = nil;
		NSData *address6 = nil;
		
		if ([remoteAddr length] >= sizeof(struct sockaddr))
		{
			const struct sockaddr *sockaddr = (const struct sockaddr *)[remoteAddr bytes];
			
			if (sockaddr->sa_family == AF_INET)
			{
				if ([remoteAddr length] == sizeof(struct sockaddr_in))
				{
					address4 = remoteAddr;
				}
			}
			else if (sockaddr->sa_family == AF_INET6)
			{
				if ([remoteAddr length] == sizeof(struct sockaddr_in6))
				{
					address6 = remoteAddr;
				}
			}
		}
		
		if ((address4 == nil) && (address6 == nil))
		{
			NSString *msg = @"A valid IPv4 or IPv6 address was not given";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
		BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
		
		if (isIPv4Disabled && (address4 != nil))
		{
			NSString *msg = @"IPv4 has been disabled and an IPv4 address was passed.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv6Disabled && (address6 != nil))
		{
			NSString *msg = @"IPv6 has been disabled and an IPv6 address was passed.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		
		if (![self preConnectWithInterface:interface error:&err])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		
		if (![self connectWithAddress4:address4 address6:address6 error:&err])
		{
			return_from_block;
		}
		
		flags |= kSocketStarted;
		
		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		if (errPtr)
			*errPtr = err;
	}
	
	return result;
}

- (BOOL)connectToUrl:(NSURL *)url withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr;
{
	LogTrace();
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
		// Check for problems with host parameter
		
		if ([url.path length] == 0)
		{
			NSString *msg = @"Invalid unix domain socket url.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		
		if (![self preConnectWithUrl:url error:&err])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		
		flags |= kSocketStarted;
		
		// Start the normal connection process
		
		NSError *connectError = nil;
		if (![self connectWithAddressUN:connectInterfaceUN error:&connectError])
		{
			[self closeWithError:connectError];
			
			return_from_block;
		}

		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		if (errPtr)
			*errPtr = err;
	}
	
	return result;
}

//连接的最终方法
- (void)lookup:(int)aStateIndex didSucceedWithAddress4:(NSData *)address4 address6:(NSData *)address6
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //至少有一个 server 地址
	NSAssert(address4 || address6, @"Expected at least one valid address");
	
    //如果状态不一致说明断开连接
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring lookupDidSucceed, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
	// Check for problems
	//分开判断
	BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
	BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
	
	if (isIPv4Disabled && (address6 == nil))
	{
		NSString *msg = @"IPv4 has been disabled and DNS lookup found no IPv6 address.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
	if (isIPv6Disabled && (address4 == nil))
	{
		NSString *msg = @"IPv6 has been disabled and DNS lookup found no IPv4 address.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
	// Start the normal connection process
	
	NSError *err = nil;
    //调用连接方法，如果失败，则错误返回
	if (![self connectWithAddress4:address4 address6:address6 error:&err])
	{
		[self closeWithError:err];
	}
}

/**
 * This method is called if the DNS lookup fails.
 * This method is executed on the socketQueue.
 * 
 * Since the DNS lookup executed synchronously on a global concurrent queue,
 * the original connection request may have already been cancelled or timed-out by the time this method is invoked.
 * The lookupIndex tells us whether the lookup is still valid or not.
**/
- (void)lookup:(int)aStateIndex didFail:(NSError *)error
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring lookup:didFail: - already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
	[self endConnectTimeout];
	[self closeWithError:error];
}

//绑定 socket 的本地地址
- (BOOL)bindSocket:(int)socketFD toInterface:(NSData *)connectInterface error:(NSError **)errPtr
{
    // Bind the socket to the desired interface (if needed)
    //无接口就不绑定， connect 会自动绑定到一个不冲突的端口上去
    if (connectInterface)
    {
        LogVerbose(@"Binding socket...");
        //判断当前的地址 Port 是不是大于0
        if ([[self class] portFromAddress:connectInterface] > 0)
        {
            // Since we're going to be binding to a specific port,
            // we should turn on reuseaddr to allow us to override sockets in time_wait.
            
            int reuseOn = 1;
            //设置调用 close(socket)后，仍可继续重用该 socket 调用 close(socket)一般都不会立即关闭 socket,而经历 TIME_WAIT 的过程
            setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        }
        //拿到地址
        const struct sockaddr *interfaceAddr = (const struct sockaddr *)[connectInterface bytes];
        //绑定这个地址
        int result = bind(socketFD, interfaceAddr, (socklen_t)[connectInterface length]);
        //绑定出错 返回0
        if (result != 0)
        {
            if (errPtr)
                *errPtr = [self errnoErrorWithReason:@"Error in bind() function"];
            
            return NO;
        }
    }
    
    return YES;
}

- (int)createSocket:(int)family connectInterface:(NSData *)connectInterface errPtr:(NSError **)errPtr
{
    //创建 socket， 用SOCK_STREAM TCP 流
    int socketFD = socket(family, SOCK_STREAM, 0);
    
    //如果创建失败
    if (socketFD == SOCKET_NULL)
    {
        if (errPtr)
            *errPtr = [self errnoErrorWithReason:@"Error in socket() function"];
        
        return socketFD;
    }
    
    //和 connectInterface 绑定
    if (![self bindSocket:socketFD toInterface:connectInterface error:errPtr])
    {
        //绑定失败，直接关闭返回
        [self closeSocket:socketFD];
        
        return SOCKET_NULL;
    }
    
    // Prevent SIGPIPE signals
    //防止终止进程的信号
    int nosigpipe = 1;
    
    //SO_NOSIGPIPE 是为了网络错误，而导致进程退出，用这个来避免系统发送 signal
    setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    
    return socketFD;
}

//连接最终方法 3
- (void)connectSocket:(int)socketFD address:(NSData *)address stateIndex:(int)aStateIndex
{
    // If there already is a socket connected, we close socketFD and return
    //已经连接， 关闭连接返回
    if (self.isConnected)
    {
        [self closeSocket:socketFD];
        return;
    }
    
    // Start the connection process in a background queue
    //开始连接过程  在后台 queue 中
    __weak GCDAsyncSocket *weakSelf = self;
    
    //获取到全局 Queue
    dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    //新线程
    dispatch_async(globalConcurrentQueue, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        //调用 connect 方法，该函数阻塞线程，所以要异步新线程
        //客户端向特定网络地址的服务器发送连接请求，连接成功返回0 失败返回 -1
        int result = connect(socketFD, (const struct sockaddr *)[address bytes], (socklen_t)[address length]);
        
        //安全判断
        __strong GCDAsyncSocket *strongSelf = weakSelf;
        if (strongSelf == nil) return_from_block;
        
        //在 socketQueue 中  开辟新线程
        dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
            
            //如果状态为已经连接，关闭连接返回
            if (strongSelf.isConnected)
            {
                [strongSelf closeSocket:socketFD];
                return_from_block;
            }
            //说明连接成功
            if (result == 0)
            {
                //关闭掉 另一个没用的socket
                [self closeUnusedSocket:socketFD];
                //调用 didConnect 生成 stream 改变状态等等
                [strongSelf didConnect:aStateIndex];
            }
            //连接诶失败
            else
            {
                //关闭当前连接
                [strongSelf closeSocket:socketFD];
                
                // If there are no more sockets trying to connect, we inform the error to the delegate
                //返回连接错误的 error
                if (strongSelf.socket4FD == SOCKET_NULL && strongSelf.socket6FD == SOCKET_NULL)
                {
                    NSError *error = [strongSelf errnoErrorWithReason:@"Error in connect() function"];
                    [strongSelf didNotConnect:aStateIndex error:error];
                }
            }
        }});
        
#pragma clang diagnostic pop
    });
    
    //输出正在连接中
    LogVerbose(@"Connecting...");
}

- (void)closeSocket:(int)socketFD
{
    if (socketFD != SOCKET_NULL &&
        (socketFD == socket6FD || socketFD == socket4FD))
    {
        close(socketFD);
        
        if (socketFD == socket4FD)
        {
            LogVerbose(@"close(socket4FD)");
            socket4FD = SOCKET_NULL;
        }
        else if (socketFD == socket6FD)
        {
            LogVerbose(@"close(socket6FD)");
            socket6FD = SOCKET_NULL;
        }
    }
}

- (void)closeUnusedSocket:(int)usedSocketFD
{
    if (usedSocketFD != socket4FD)
    {
        [self closeSocket:socket4FD];
    }
    else if (usedSocketFD != socket6FD)
    {
        [self closeSocket:socket6FD];
    }
}

//连接的最终方法2。 用两个 server 地址去连接，失败返回 NO, 并填充 error
- (BOOL)connectWithAddress4:(NSData *)address4 address6:(NSData *)address6 error:(NSError **)errPtr
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
    //输出一些东西
	LogVerbose(@"IPv4: %@:%hu", [[self class] hostFromAddress:address4], [[self class] portFromAddress:address4]);
	LogVerbose(@"IPv6: %@:%hu", [[self class] hostFromAddress:address6], [[self class] portFromAddress:address6]);
	
	// Determine socket type
	
    //判断是否倾向于 IPV6
	BOOL preferIPv6 = (config & kPreferIPv6) ? YES : NO;
	
	// Create and bind the sockets
    
    //如果有 IPV4地址，创建 IPV4 Socket
    if (address4)
    {
        LogVerbose(@"Creating IPv4 socket");
        
        socket4FD = [self createSocket:AF_INET connectInterface:connectInterface4 errPtr:errPtr];
    }
    
    //如果有 IPV6地址，创建 IPV6 Socket
    if (address6)
    {
        LogVerbose(@"Creating IPv6 socket");
        
        socket6FD = [self createSocket:AF_INET6 connectInterface:connectInterface6 errPtr:errPtr];
    }
    
    //如果都为空直接返回
    if (socket4FD == SOCKET_NULL && socket6FD == SOCKET_NULL)
    {
        return NO;
    }
	//主选socketFD， 备选alternateSocketFD
	int socketFD, alternateSocketFD;
    //主选地址 和 备选地址
	NSData *address, *alternateAddress;
	
    //IPV6
    if ((preferIPv6 && socket6FD != SOCKET_NULL) || socket4FD == SOCKET_NULL)
    {
        socketFD = socket6FD;
        alternateSocketFD = socket4FD;
        address = address6;
        alternateAddress = address4;
    }
    //主选 IPV4
    else
    {
        socketFD = socket4FD;
        alternateSocketFD = socket6FD;
        address = address4;
        alternateAddress = address6;
    }
    //拿到当前状态
    int aStateIndex = stateIndex;
    //用 socket 和 address 去连接
    [self connectSocket:socketFD address:address stateIndex:aStateIndex];
    
    //如果有备选地址
    if (alternateAddress)
    {
        //延迟去连接备选地址
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(alternateAddressDelay * NSEC_PER_SEC)), socketQueue, ^{
            [self connectSocket:alternateSocketFD address:alternateAddress stateIndex:aStateIndex];
        });
    }
	
	return YES;
}

//连接 Unix 域服务器
- (BOOL)connectWithAddressUN:(NSData *)address error:(NSError **)errPtr
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	// Create the socket
	
	int socketFD;
	
	LogVerbose(@"Creating unix domain socket");
	
    //创建本机 socket
	socketUN = socket(AF_UNIX, SOCK_STREAM, 0);
	
	socketFD = socketUN;
	
	if (socketFD == SOCKET_NULL)
	{
		if (errPtr)
			*errPtr = [self errnoErrorWithReason:@"Error in socket() function"];
		
		return NO;
	}
	
	// Bind the socket to the desired interface (if needed)
	
	LogVerbose(@"Binding socket...");
	
	int reuseOn = 1;
    
    //设置可复用
	setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));

//	const struct sockaddr *interfaceAddr = (const struct sockaddr *)[address bytes];
//	
//	int result = bind(socketFD, interfaceAddr, (socklen_t)[address length]);
//	if (result != 0)
//	{
//		if (errPtr)
//			*errPtr = [self errnoErrorWithReason:@"Error in bind() function"];
//		
//		return NO;
//	}
	
	// Prevent SIGPIPE signals
	
	int nosigpipe = 1;
    //进程终止错误信号禁止
	setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
	
	// Start the connection process in a background queue
	
	int aStateIndex = stateIndex;
	
	dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	dispatch_async(globalConcurrentQueue, ^{
		
		const struct sockaddr *addr = (const struct sockaddr *)[address bytes];
        //并行队列调用连接
		int result = connect(socketFD, addr, addr->sa_len);
		if (result == 0)
		{
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				//连接成功的一些状态初始化
				[self didConnect:aStateIndex];
			}});
		}
		else
		{
			// TODO: Bad file descriptor
            
            //失败处理
			perror("connect");
			NSError *error = [self errnoErrorWithReason:@"Error in connect() function"];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self didNotConnect:aStateIndex error:error];
			}});
		}
	});
	
	LogVerbose(@"Connecting...");
	
	return YES;
}

//连接成功后调用，设置一些连接成功的状态
- (void)didConnect:(int)aStateIndex
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	//状态不同
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring didConnect, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
    //kConnected 合并到当前 flag 中
	flags |= kConnected;
	
    //停止连接超时
	[self endConnectTimeout];
	
	#if TARGET_OS_IPHONE
	// The endConnectTimeout method executed above incremented the stateIndex.
    //上面 endConnectTimeout，会导致stateIndex 增加，所以需要重新赋值
	aStateIndex = stateIndex;
	#endif
	
	// Setup read/write streams (as workaround for specific shortcomings in the iOS platform)
	// 
	// Note:
	// There may be configuration options that must be set by the delegate before opening the streams.
    // 打开 stream 之前必须用相关配置设置代理
	// The primary example is the kCFStreamNetworkServiceTypeVoIP flag, which only works on an unopened stream.
    //主要的例子是kCFStreamNetworkServiceTypeVoIP 标记，只能工作在未打开的 stream中
	// 
	// Thus we wait until after the socket:didConnectToHost:port: delegate method has completed.
    // 所以我们要等待，连接完成的代理调用完
	// This gives the delegate time to properly configure the streams if needed.
    //这些给了代理时间 去正确的配置 stream,如果是必要的话
	
    //创建个 Block 来初始化 Stream
	dispatch_block_t SetupStreamsPart1 = ^{
		#if TARGET_OS_IPHONE
		
        //创建读写 Stream 失败，则关闭并报对应的错误
		if (![self createReadAndWriteStream])
		{
			[self closeWithError:[self otherError:@"Error creating CFStreams"]];
			return;
		}
		
        //参数是给 NO 的， 就是有可读 bytes 的时候，不会调用回调函数
		if (![self registerForStreamCallbacksIncludingReadWrite:NO])
		{
			[self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
			return;
		}
		
		#endif
	};
    
    //设置 stream
	dispatch_block_t SetupStreamsPart2 = ^{
		#if TARGET_OS_IPHONE
		//状态不一样直接返回
		if (aStateIndex != stateIndex)
		{
			// The socket has been disconnected.
			return;
		}
		
        //如果加到 runloop 上失败
		if (![self addStreamsToRunLoop])
		{
            //错误返回
			[self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
			return;
		}
		
        //读写 stream open
		if (![self openStreams])
		{
            //开启错误返回
			[self closeWithError:[self otherError:@"Error creating CFStreams"]];
			return;
		}
		
		#endif
	};
	
	// Notify delegate
    
    //通知代理
    //拿到 server 端的 host port
	
	NSString *host = [self connectedHost];
	uint16_t port = [self connectedPort];
	
    //拿到 unix 域的 url
    NSURL *url = [self connectedUrl];
    
	//拿到代理
	__strong id theDelegate = delegate;

    //代理队列 和 Host 不为 nil  且响应 didConnectToHost代理方法
	if (delegateQueue && host != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToHost:port:)])
	{
        //调用初始化 stream
		SetupStreamsPart1();
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
            //到代理队列调用连接成功代理方法
			[theDelegate socket:self didConnectToHost:host port:port];
			
            //然后回到 socketQueue 中去执行初始化 stream2
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				SetupStreamsPart2();
			}});
		}});
	}
    //这个是 unix domain 请求回调
	else if (delegateQueue && url != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToUrl:)])
	{
		SetupStreamsPart1();
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			[theDelegate socket:self didConnectToUrl:url];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				SetupStreamsPart2();
			}});
		}});
	}
	else
	{
        //否则只初始化 stream
		SetupStreamsPart1();
		SetupStreamsPart2();
	}
		
	// Get the connected socket
	
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	
    
    //fcntl 功能描述： 根据文件描述词来操作文件特征。
	// Enable non-blocking IO on the socket
	// 使 socket 支持非阻塞 IO
	int result = fcntl(socketFD, F_SETFL, O_NONBLOCK);
	if (result == -1)
	{
        //失败 报错
		NSString *errMsg = @"Error enabling non-blocking IO on socket (fcntl)";
		[self closeWithError:[self otherError:errMsg]];
		
		return;
	}
	
	// Setup our read/write sources
	//初始化读写 source
	[self setupReadAndWriteSourcesForNewlyConnectedSocket:socketFD];
	
	// Dequeue any pending read/write requests
	
    //开始下一个任务
	[self maybeDequeueRead];
	[self maybeDequeueWrite];
}

- (void)didNotConnect:(int)aStateIndex error:(NSError *)error
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring didNotConnect, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
	[self closeWithError:error];
}

- (void)startConnectTimeout:(NSTimeInterval)timeout
{
	if (timeout >= 0.0)
	{
		connectTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
		dispatch_source_set_event_handler(connectTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			
			[strongSelf doConnectTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
		dispatch_source_t theConnectTimer = connectTimer;
		dispatch_source_set_cancel_handler(connectTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(connectTimer)");
			dispatch_release(theConnectTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
		
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
		dispatch_source_set_timer(connectTimer, tt, DISPATCH_TIME_FOREVER, 0);
		
		dispatch_resume(connectTimer);
	}
}

- (void)endConnectTimeout
{
	LogTrace();
	
	if (connectTimer)
	{
		dispatch_source_cancel(connectTimer);
		connectTimer = NULL;
	}
	
	// Increment stateIndex.
	// This will prevent us from processing results from any related background asynchronous operations.
	// 
	// Note: This should be called from close method even if connectTimer is NULL.
	// This is because one might disconnect a socket prior to a successful connection which had no timeout.
	
	stateIndex++;
	
	if (connectInterface4)
	{
		connectInterface4 = nil;
	}
	if (connectInterface6)
	{
		connectInterface6 = nil;
	}
}

- (void)doConnectTimeout
{
	LogTrace();
	
	[self endConnectTimeout];
	[self closeWithError:[self connectTimeoutError]];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Disconnecting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)closeWithError:(NSError *)error
{
	LogTrace();
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	[self endConnectTimeout];
	
	if (currentRead != nil)  [self endCurrentRead];
	if (currentWrite != nil) [self endCurrentWrite];
	
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	[preBuffer reset];
	
	#if TARGET_OS_IPHONE
	{
		if (readStream || writeStream)
		{
			[self removeStreamsFromRunLoop];
			
			if (readStream)
			{
				CFReadStreamSetClient(readStream, kCFStreamEventNone, NULL, NULL);
				CFReadStreamClose(readStream);
				CFRelease(readStream);
				readStream = NULL;
			}
			if (writeStream)
			{
				CFWriteStreamSetClient(writeStream, kCFStreamEventNone, NULL, NULL);
				CFWriteStreamClose(writeStream);
				CFRelease(writeStream);
				writeStream = NULL;
			}
		}
	}
	#endif
	
	[sslPreBuffer reset];
	sslErrCode = lastSSLHandshakeError = noErr;
	
	if (sslContext)
	{
		// Getting a linker error here about the SSLx() functions?
		// You need to add the Security Framework to your application.
		
		SSLClose(sslContext);
		
		#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
		CFRelease(sslContext);
		#else
		SSLDisposeContext(sslContext);
		#endif
		
		sslContext = NULL;
	}
	
	// For some crazy reason (in my opinion), cancelling a dispatch source doesn't
	// invoke the cancel handler if the dispatch source is paused.
	// So we have to unpause the source if needed.
	// This allows the cancel handler to be run, which in turn releases the source and closes the socket.
	
	if (!accept4Source && !accept6Source && !acceptUNSource && !readSource && !writeSource)
	{
		LogVerbose(@"manually closing close");

		if (socket4FD != SOCKET_NULL)
		{
			LogVerbose(@"close(socket4FD)");
			close(socket4FD);
			socket4FD = SOCKET_NULL;
		}

		if (socket6FD != SOCKET_NULL)
		{
			LogVerbose(@"close(socket6FD)");
			close(socket6FD);
			socket6FD = SOCKET_NULL;
		}
		
		if (socketUN != SOCKET_NULL)
		{
			LogVerbose(@"close(socketUN)");
			close(socketUN);
			socketUN = SOCKET_NULL;
			unlink(socketUrl.path.fileSystemRepresentation);
			socketUrl = nil;
		}
	}
	else
	{
		if (accept4Source)
		{
			LogVerbose(@"dispatch_source_cancel(accept4Source)");
			dispatch_source_cancel(accept4Source);
			
			// We never suspend accept4Source
			
			accept4Source = NULL;
		}
		
		if (accept6Source)
		{
			LogVerbose(@"dispatch_source_cancel(accept6Source)");
			dispatch_source_cancel(accept6Source);
			
			// We never suspend accept6Source
			
			accept6Source = NULL;
		}
		
		if (acceptUNSource)
		{
			LogVerbose(@"dispatch_source_cancel(acceptUNSource)");
			dispatch_source_cancel(acceptUNSource);
			
			// We never suspend acceptUNSource
			
			acceptUNSource = NULL;
		}
	
		if (readSource)
		{
			LogVerbose(@"dispatch_source_cancel(readSource)");
			dispatch_source_cancel(readSource);
			
			[self resumeReadSource];
			
			readSource = NULL;
		}
		
		if (writeSource)
		{
			LogVerbose(@"dispatch_source_cancel(writeSource)");
			dispatch_source_cancel(writeSource);
			
			[self resumeWriteSource];
			
			writeSource = NULL;
		}
		
		// The sockets will be closed by the cancel handlers of the corresponding source
		
		socket4FD = SOCKET_NULL;
		socket6FD = SOCKET_NULL;
		socketUN = SOCKET_NULL;
	}
	
	// If the client has passed the connect/accept method, then the connection has at least begun.
	// Notify delegate that it is now ending.
	BOOL shouldCallDelegate = (flags & kSocketStarted) ? YES : NO;
	BOOL isDeallocating = (flags & kDealloc) ? YES : NO;
	
	// Clear stored socket info and all flags (config remains as is)
	socketFDBytesAvailable = 0;
	flags = 0;
	sslWriteCachedLength = 0;
	
	if (shouldCallDelegate)
	{
		__strong id theDelegate = delegate;
		__strong id theSelf = isDeallocating ? nil : self;
		
		if (delegateQueue && [theDelegate respondsToSelector: @selector(socketDidDisconnect:withError:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socketDidDisconnect:theSelf withError:error];
			}});
		}	
	}
}

- (void)disconnect
{
	dispatch_block_t block = ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			[self closeWithError:nil];
		}
	}};
	
	// Synchronous disconnection, as documented in the header file
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
}

- (void)disconnectAfterReading
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterReads);
			[self maybeClose];
		}
	}});
}

- (void)disconnectAfterWriting
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterWrites);
			[self maybeClose];
		}
	}});
}

- (void)disconnectAfterReadingAndWriting
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterReads | kDisconnectAfterWrites);
			[self maybeClose];
		}
	}});
}

/**
 * Closes the socket if possible.
 * That is, if all writes have completed, and we're set to disconnect after writing,
 * or if all reads have completed, and we're set to disconnect after reading.
**/
- (void)maybeClose
{
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	BOOL shouldClose = NO;
	
	if (flags & kDisconnectAfterReads)
	{
		if (([readQueue count] == 0) && (currentRead == nil))
		{
			if (flags & kDisconnectAfterWrites)
			{
				if (([writeQueue count] == 0) && (currentWrite == nil))
				{
					shouldClose = YES;
				}
			}
			else
			{
				shouldClose = YES;
			}
		}
	}
	else if (flags & kDisconnectAfterWrites)
	{
		if (([writeQueue count] == 0) && (currentWrite == nil))
		{
			shouldClose = YES;
		}
	}
	
	if (shouldClose)
	{
		[self closeWithError:nil];
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Errors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSError *)badConfigError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketBadConfigError userInfo:userInfo];
}

//用该字符串生成一个错误，错误的域名，错误的参数
- (NSError *)badParamError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketBadParamError userInfo:userInfo];
}

+ (NSError *)gaiError:(int)gai_error
{
	NSString *errMsg = [NSString stringWithCString:gai_strerror(gai_error) encoding:NSASCIIStringEncoding];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:@"kCFStreamErrorDomainNetDB" code:gai_error userInfo:userInfo];
}

- (NSError *)errnoErrorWithReason:(NSString *)reason
{
	NSString *errMsg = [NSString stringWithUTF8String:strerror(errno)];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:errMsg, NSLocalizedDescriptionKey,
	                                                                    reason, NSLocalizedFailureReasonErrorKey, nil];
	
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:userInfo];
}

- (NSError *)errnoError
{
	NSString *errMsg = [NSString stringWithUTF8String:strerror(errno)];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:userInfo];
}

- (NSError *)sslError:(OSStatus)ssl_error
{
	NSString *msg = @"Error code definition can be found in Apple's SecureTransport.h";
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:msg forKey:NSLocalizedRecoverySuggestionErrorKey];
	
	return [NSError errorWithDomain:@"kCFStreamErrorDomainSSL" code:ssl_error userInfo:userInfo];
}

- (NSError *)connectTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketConnectTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Attempt to connect to host timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketConnectTimeoutError userInfo:userInfo];
}

/**
 * Returns a standard AsyncSocket maxed out error.
**/
- (NSError *)readMaxedOutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketReadMaxedOutError",
														 @"GCDAsyncSocket", [NSBundle mainBundle],
														 @"Read operation reached set maximum length", nil);
	
	NSDictionary *info = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketReadMaxedOutError userInfo:info];
}

/**
 * Returns a standard AsyncSocket write timeout error.
**/
- (NSError *)readTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketReadTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Read operation timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketReadTimeoutError userInfo:userInfo];
}

/**
 * Returns a standard AsyncSocket write timeout error.
**/
- (NSError *)writeTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketWriteTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Write operation timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketWriteTimeoutError userInfo:userInfo];
}

- (NSError *)connectionClosedError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketClosedError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Socket closed by remote peer", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketClosedError userInfo:userInfo];
}

- (NSError *)otherError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketOtherError userInfo:userInfo];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Diagnostics
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (BOOL)isDisconnected
{
	__block BOOL result = NO;
	
	dispatch_block_t block = ^{
		result = (flags & kSocketStarted) ? NO : YES;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (BOOL)isConnected
{
	__block BOOL result = NO;
	
	dispatch_block_t block = ^{
		result = (flags & kConnected) ? YES : NO;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (NSString *)connectedHost
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self connectedHostFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self connectedHostFromSocket6:socket6FD];
		
		return nil;
	}
	else
	{
		__block NSString *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socket4FD != SOCKET_NULL)
				result = [self connectedHostFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self connectedHostFromSocket6:socket6FD];
		}});
		
		return result;
	}
}

- (uint16_t)connectedPort
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self connectedPortFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self connectedPortFromSocket6:socket6FD];
		
		return 0;
	}
	else
	{
		__block uint16_t result = 0;
		
		dispatch_sync(socketQueue, ^{
			// No need for autorelease pool
			
			if (socket4FD != SOCKET_NULL)
				result = [self connectedPortFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self connectedPortFromSocket6:socket6FD];
		});
		
		return result;
	}
}

- (NSURL *)connectedUrl
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socketUN != SOCKET_NULL)
			return [self connectedUrlFromSocketUN:socketUN];
		
		return nil;
	}
	else
	{
		__block NSURL *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socketUN != SOCKET_NULL)
				result = [self connectedUrlFromSocketUN:socketUN];
		}});
		
		return result;
	}
}

- (NSString *)localHost
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self localHostFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self localHostFromSocket6:socket6FD];
		
		return nil;
	}
	else
	{
		__block NSString *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socket4FD != SOCKET_NULL)
				result = [self localHostFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self localHostFromSocket6:socket6FD];
		}});
		
		return result;
	}
}

- (uint16_t)localPort
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self localPortFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self localPortFromSocket6:socket6FD];
		
		return 0;
	}
	else
	{
		__block uint16_t result = 0;
		
		dispatch_sync(socketQueue, ^{
			// No need for autorelease pool
			
			if (socket4FD != SOCKET_NULL)
				result = [self localPortFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self localPortFromSocket6:socket6FD];
		});
		
		return result;
	}
}

- (NSString *)connectedHost4
{
	if (socket4FD != SOCKET_NULL)
		return [self connectedHostFromSocket4:socket4FD];
	
	return nil;
}

- (NSString *)connectedHost6
{
	if (socket6FD != SOCKET_NULL)
		return [self connectedHostFromSocket6:socket6FD];
	
	return nil;
}

- (uint16_t)connectedPort4
{
	if (socket4FD != SOCKET_NULL)
		return [self connectedPortFromSocket4:socket4FD];
	
	return 0;
}

- (uint16_t)connectedPort6
{
	if (socket6FD != SOCKET_NULL)
		return [self connectedPortFromSocket6:socket6FD];
	
	return 0;
}

- (NSString *)localHost4
{
	if (socket4FD != SOCKET_NULL)
		return [self localHostFromSocket4:socket4FD];
	
	return nil;
}

- (NSString *)localHost6
{
	if (socket6FD != SOCKET_NULL)
		return [self localHostFromSocket6:socket6FD];
	
	return nil;
}

- (uint16_t)localPort4
{
	if (socket4FD != SOCKET_NULL)
		return [self localPortFromSocket4:socket4FD];
	
	return 0;
}

- (uint16_t)localPort6
{
	if (socket6FD != SOCKET_NULL)
		return [self localPortFromSocket6:socket6FD];
	
	return 0;
}

- (NSString *)connectedHostFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr4:&sockaddr4];
}

- (NSString *)connectedHostFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr6:&sockaddr6];
}

- (uint16_t)connectedPortFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr4:&sockaddr4];
}

- (uint16_t)connectedPortFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr6:&sockaddr6];
}

- (NSURL *)connectedUrlFromSocketUN:(int)socketFD
{
	struct sockaddr_un sockaddr;
	socklen_t sockaddrlen = sizeof(sockaddr);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr, &sockaddrlen) < 0)
	{
		return 0;
	}
	return [[self class] urlFromSockaddrUN:&sockaddr];
}

- (NSString *)localHostFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr4:&sockaddr4];
}

- (NSString *)localHostFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr6:&sockaddr6];
}

- (uint16_t)localPortFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr4:&sockaddr4];
}

- (uint16_t)localPortFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr6:&sockaddr6];
}

- (NSData *)connectedAddress
{
	__block NSData *result = nil;
	
	dispatch_block_t block = ^{
		if (socket4FD != SOCKET_NULL)
		{
			struct sockaddr_in sockaddr4;
			socklen_t sockaddr4len = sizeof(sockaddr4);
			
			if (getpeername(socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
			}
		}
		
		if (socket6FD != SOCKET_NULL)
		{
			struct sockaddr_in6 sockaddr6;
			socklen_t sockaddr6len = sizeof(sockaddr6);
			
			if (getpeername(socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
			}
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (NSData *)localAddress
{
	__block NSData *result = nil;
	
	dispatch_block_t block = ^{
		if (socket4FD != SOCKET_NULL)
		{
			struct sockaddr_in sockaddr4;
			socklen_t sockaddr4len = sizeof(sockaddr4);
			
			if (getsockname(socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
			}
		}
		
		if (socket6FD != SOCKET_NULL)
		{
			struct sockaddr_in6 sockaddr6;
			socklen_t sockaddr6len = sizeof(sockaddr6);
			
			if (getsockname(socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
			}
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (BOOL)isIPv4
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (socket4FD != SOCKET_NULL);
	}
	else
	{
		__block BOOL result = NO;
		
		dispatch_sync(socketQueue, ^{
			result = (socket4FD != SOCKET_NULL);
		});
		
		return result;
	}
}

- (BOOL)isIPv6
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (socket6FD != SOCKET_NULL);
	}
	else
	{
		__block BOOL result = NO;
		
		dispatch_sync(socketQueue, ^{
			result = (socket6FD != SOCKET_NULL);
		});
		
		return result;
	}
}

- (BOOL)isSecure
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (flags & kSocketSecure) ? YES : NO;
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = (flags & kSocketSecure) ? YES : NO;
		});
		
		return result;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Finds the address of an interface description.
 * An inteface description may be an interface name (en0, en1, lo0) or corresponding IP (192.168.4.34).
 * 
 * The interface description may optionally contain a port number at the end, separated by a colon.
 * If a non-zero port parameter is provided, any port number in the interface description is ignored.
 * 
 * The returned value is a 'struct sockaddr' wrapped in an NSMutableData object.
**/
- (void)getInterfaceAddress4:(NSMutableData **)interfaceAddr4Ptr
                    address6:(NSMutableData **)interfaceAddr6Ptr
             fromDescription:(NSString *)interfaceDescription
                        port:(uint16_t)port
{
	NSMutableData *addr4 = nil;
	NSMutableData *addr6 = nil;
	
	NSString *interface = nil;
	//先用 ：  分割
	NSArray *components = [interfaceDescription componentsSeparatedByString:@":"];
	if ([components count] > 0)
	{
		NSString *temp = [components objectAtIndex:0];
		if ([temp length] > 0)
		{
			interface = temp;
		}
	}
	if ([components count] > 1 && port == 0)
	{
        //拿到 port strtol函数，将一个字符串，根据 base 参数转成长整型，如 base值为10则采用10进制，若 base 值为16 则采用16进制
		long portL = strtol([[components objectAtIndex:1] UTF8String], NULL, 10);
		//UINI16_MAX  65535最大端口
		if (portL > 0 && portL <= UINT16_MAX)
		{
			port = (uint16_t)portL;
		}
	}
	
    //为空则自己创建一个  0x00000000, 全是0， 为线路地址
    //如果端口为0   通常用于分析操作系统，这一方法能够工作是因为在一些系统中 ”0“是无效端口，当你试图使用通常的闭合端口连接它时将产生不同的效果。
    //一种典型的扫描，使用 IP 地址为0.0.0.0， 设置 ACK位并在以太网层广播
	if (interface == nil)
	{
		// ANY address
		
		struct sockaddr_in sockaddr4;
        
        //memset 作用是在一段内存中填充某个给定的值，它是对较大的结构体或数组进行清零操作的一种最快方法
        //第一个参数为指针地址， 第二个为设置值  第三个为连续设置的长度（大小）
		memset(&sockaddr4, 0, sizeof(sockaddr4));
		
        //结构体长度
		sockaddr4.sin_len         = sizeof(sockaddr4);
		sockaddr4.sin_family      = AF_INET;
        //端口号 htons 将主机字节顺序转换成网络字节顺序  16位
		sockaddr4.sin_port        = htons(port);
        
        //htonl 将INADDR_ANY：0.0.0.0 不确定地址， 或者任意地址  htonl 32位。  也是转换为网络字节序
        //ipv4 32位 4个字节  INADDR_ANY 0x00000000（16进制， 一个0代表4， 8个0就是32位） = 4个字节的
		sockaddr4.sin_addr.s_addr = htonl(INADDR_ANY);
		
		struct sockaddr_in6 sockaddr6;
		memset(&sockaddr6, 0, sizeof(sockaddr6));
		
		sockaddr6.sin6_len       = sizeof(sockaddr6);
        //ipv6
		sockaddr6.sin6_family    = AF_INET6;
        //port
		sockaddr6.sin6_port      = htons(port);
        //共128位
		sockaddr6.sin6_addr      = in6addr_any;
		//把这两个结构体转换成 data
		addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
		addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
	}
    //如果 localhost,loopback 回环地址，虚拟地址，路由器工作它就存在。一般用来标识路由器
    //这两种的话就是赋值为127.0.0.1 端口为 port
	else if ([interface isEqualToString:@"localhost"] || [interface isEqualToString:@"loopback"])
	{
		// LOOPBACK address
		//ipv4
		struct sockaddr_in sockaddr4;
		memset(&sockaddr4, 0, sizeof(sockaddr4));
		
		sockaddr4.sin_len         = sizeof(sockaddr4);
		sockaddr4.sin_family      = AF_INET;
		sockaddr4.sin_port        = htons(port);
		sockaddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		
		struct sockaddr_in6 sockaddr6;
		memset(&sockaddr6, 0, sizeof(sockaddr6));
		
		sockaddr6.sin6_len       = sizeof(sockaddr6);
		sockaddr6.sin6_family    = AF_INET6;
		sockaddr6.sin6_port      = htons(port);
		sockaddr6.sin6_addr      = in6addr_loopback;
		
        //赋值
		addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
		addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
	}
	else
	{
        //非 localhost、loopback 去获取本机 IP,看和传进来 Interface 是同名或者同 IP,相同才给赋端口，把数据封装成 Data,否则为 nil
        //转成 cString
		const char *iface = [interface UTF8String];
		
        //定义结构体指针，这个指针是本机 IP
		struct ifaddrs *addrs;
		const struct ifaddrs *cursor;
		//获取本机 IP, 为0说明成功了
		if ((getifaddrs(&addrs) == 0))
		{
            //赋值
			cursor = addrs;
            //如果 IP 不为空，则循环链表设置
			while (cursor != NULL)
			{
                //如果 addr4 IPV4地址为空，而且地址类型为 IPV4
				if ((addr4 == nil) && (cursor->ifa_addr->sa_family == AF_INET))
				{
					// IPv4
					
					struct sockaddr_in nativeAddr4;
                    //memcpy内存 copy 函数，把 src 开始到 size 的字节数 copy 到 dest 中
					memcpy(&nativeAddr4, cursor->ifa_addr, sizeof(nativeAddr4));
					//比较两个字符串是否相同，本机的 IP 名和接口 interface 是否相同
					if (strcmp(cursor->ifa_name, iface) == 0)
					{
						// Name match
						//相同则赋值 port
						nativeAddr4.sin_port = htons(port);
						//用 data 封号 IPV4地址
						addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
					}
                    //本机 IP 名和 Interface 不相同
					else
					{
                        //声明一个 IP16位的数组
						char ip[INET_ADDRSTRLEN];
						//这里是转成10进制 （因为获取的是二进制 IP）
						const char *conversion = inet_ntop(AF_INET, &nativeAddr4.sin_addr, ip, sizeof(ip));
						//如果 conversion 不为空，说明转换成功，而且比较转换后的 IP 和 interface 是否相同
						if ((conversion != NULL) && (strcmp(ip, iface) == 0))
						{
							// IP match
							//相同则赋值 port
							nativeAddr4.sin_port = htons(port);
							
							addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
						}
					}
				}
				else if ((addr6 == nil) && (cursor->ifa_addr->sa_family == AF_INET6))
				{
					// IPv6
					
					struct sockaddr_in6 nativeAddr6;
					memcpy(&nativeAddr6, cursor->ifa_addr, sizeof(nativeAddr6));
					
					if (strcmp(cursor->ifa_name, iface) == 0)
					{
						// Name match
						
						nativeAddr6.sin6_port = htons(port);
						
						addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
					}
					else
					{
						char ip[INET6_ADDRSTRLEN];
						
						const char *conversion = inet_ntop(AF_INET6, &nativeAddr6.sin6_addr, ip, sizeof(ip));
						
						if ((conversion != NULL) && (strcmp(ip, iface) == 0))
						{
							// IP match
							
							nativeAddr6.sin6_port = htons(port);
							
							addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
						}
					}
				}
				// 指向链表下一个 addr
				cursor = cursor->ifa_next;
			}
			//和 getifaddrs 对应， 释放这部分内存
			freeifaddrs(addrs);
		}
	}
	
    //如果这两个二级指针存在，则取成一级指针，把 addr4赋值给他
	if (interfaceAddr4Ptr) *interfaceAddr4Ptr = addr4;
	if (interfaceAddr6Ptr) *interfaceAddr6Ptr = addr6;
}

- (NSData *)getInterfaceAddressFromUrl:(NSURL *)url;
{
	NSString *path = url.path;
	if (path.length == 0) {
		return nil;
	}
	
    struct sockaddr_un nativeAddr;
    nativeAddr.sun_family = AF_UNIX;
    strlcpy(nativeAddr.sun_path, path.fileSystemRepresentation, sizeof(nativeAddr.sun_path));
    nativeAddr.sun_len = SUN_LEN(&nativeAddr);
    NSData *interface = [NSData dataWithBytes:&nativeAddr length:sizeof(struct sockaddr_un)];
	
	return interface;
}

//初始化读写 source
- (void)setupReadAndWriteSourcesForNewlyConnectedSocket:(int)socketFD
{
    //GCD source DISPATCH_SOURCE_TYPE_READ 会一直监视着 socketFD 直到有数据可读
	readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socketFD, 0, socketQueue);
    
    //DISPATCH_SOURCE_TYPE_WRITE 监视着socketFD 直到写数据了
	writeSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, socketFD, 0, socketQueue);
	
	// Setup event handlers
	
	__weak GCDAsyncSocket *weakSelf = self;
	//GCD 时间句柄读， 当 socket 中有数据流出现，就会触发这个句柄，全自动， 不需要手动触发
	dispatch_source_set_event_handler(readSource, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		__strong GCDAsyncSocket *strongSelf = weakSelf;
		if (strongSelf == nil) return_from_block;
		
		LogVerbose(@"readEventBlock");
        
        //从readEventBlock 中获取到数据长度
		
		strongSelf->socketFDBytesAvailable = dispatch_source_get_data(strongSelf->readSource);
		LogVerbose(@"socketFDBytesAvailable: %lu", strongSelf->socketFDBytesAvailable);
		
        //如果长度大于0 开始读数据
		if (strongSelf->socketFDBytesAvailable > 0)
			[strongSelf doReadData];
		else
            //因为触发了，但是却没有可读数据，说明读到当前包边界了，做边界处理
			[strongSelf doReadEOF];
		
	#pragma clang diagnostic pop
	}});
	
    
    //写事件句柄
	dispatch_source_set_event_handler(writeSource, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		__strong GCDAsyncSocket *strongSelf = weakSelf;
		if (strongSelf == nil) return_from_block;
		
		LogVerbose(@"writeEventBlock");
		
        //标记为接收数据
		strongSelf->flags |= kSocketCanAcceptBytes;
        //开始写
		[strongSelf doWriteData];
		
	#pragma clang diagnostic pop
	}});
	
	// Setup cancel handlers
	
	__block int socketFDRefCount = 2;
	
	#if !OS_OBJECT_USE_OBJC
	dispatch_source_t theReadSource = readSource;
	dispatch_source_t theWriteSource = writeSource;
	#endif
	
    //读写取消句柄
	dispatch_source_set_cancel_handler(readSource, ^{
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		LogVerbose(@"readCancelBlock");
		
		#if !OS_OBJECT_USE_OBJC
		LogVerbose(@"dispatch_release(readSource)");
		dispatch_release(theReadSource);
		#endif
		
		if (--socketFDRefCount == 0)
		{
			LogVerbose(@"close(socketFD)");
            //关闭 socket
			close(socketFD);
		}
		
	#pragma clang diagnostic pop
	});
	
	dispatch_source_set_cancel_handler(writeSource, ^{
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		LogVerbose(@"writeCancelBlock");
		
		#if !OS_OBJECT_USE_OBJC
		LogVerbose(@"dispatch_release(writeSource)");
		dispatch_release(theWriteSource);
		#endif
		
		if (--socketFDRefCount == 0)
		{
			LogVerbose(@"close(socketFD)");
			close(socketFD);
		}
		
	#pragma clang diagnostic pop
	});
	
	// We will not be able to read until data arrives.
	// But we should be able to write immediately.
	
    //设置未读数量为0
	socketFDBytesAvailable = 0;
    //把读挂起的状态移除
	flags &= ~kReadSourceSuspended;
	
	LogVerbose(@"dispatch_resume(readSource)");
    //开启读 source
	dispatch_resume(readSource);
	
    //标记为当前可接收数据
	flags |= kSocketCanAcceptBytes;
    //先把写 source 标记为挂起
	flags |= kWriteSourceSuspended;
}

- (BOOL)usingCFStreamForTLS
{
	#if TARGET_OS_IPHONE
	
	if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
	{
		// The startTLS method was given the GCDAsyncSocketUseCFStreamForTLS flag.
		
		return YES;
	}
	
	#endif
	
	return NO;
}

- (BOOL)usingSecureTransportForTLS
{
	// Invoking this method is equivalent to ![self usingCFStreamForTLS] (just more readable)
	
	#if TARGET_OS_IPHONE
	
	if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
	{
		// The startTLS method was given the GCDAsyncSocketUseCFStreamForTLS flag.
		
		return NO;
	}
	
	#endif
	
	return YES;
}

- (void)suspendReadSource
{
	if (!(flags & kReadSourceSuspended))
	{
		LogVerbose(@"dispatch_suspend(readSource)");
		
		dispatch_suspend(readSource);
		flags |= kReadSourceSuspended;
	}
}

- (void)resumeReadSource
{
	if (flags & kReadSourceSuspended)
	{
		LogVerbose(@"dispatch_resume(readSource)");
		
		dispatch_resume(readSource);
		flags &= ~kReadSourceSuspended;
	}
}

- (void)suspendWriteSource
{
	if (!(flags & kWriteSourceSuspended))
	{
		LogVerbose(@"dispatch_suspend(writeSource)");
		
		dispatch_suspend(writeSource);
		flags |= kWriteSourceSuspended;
	}
}

- (void)resumeWriteSource
{
	if (flags & kWriteSourceSuspended)
	{
		LogVerbose(@"dispatch_resume(writeSource)");
		
		dispatch_resume(writeSource);
		flags &= ~kWriteSourceSuspended;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Reading
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)readDataWithTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                        tag:(long)tag
{
	[self readDataWithTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

//用偏移量 maxLength 读取数据
- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                  maxLength:(NSUInteger)length
                        tag:(long)tag
{
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:length
	                                                              timeout:timeout
	                                                           readLength:0
	                                                           terminator:nil
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
            //往队列添加任务，任务是包的形式
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (void)readDataToLength:(NSUInteger)length withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataToLength:length withTimeout:timeout buffer:nil bufferOffset:0 tag:tag];
}

- (void)readDataToLength:(NSUInteger)length
             withTimeout:(NSTimeInterval)timeout
                  buffer:(NSMutableData *)buffer
            bufferOffset:(NSUInteger)offset
                     tag:(long)tag
{
	if (length == 0) {
		LogWarn(@"Cannot read: length == 0");
		return;
	}
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:0
	                                                              timeout:timeout
	                                                           readLength:length
	                                                           terminator:nil
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
                   tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:length tag:tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
             maxLength:(NSUInteger)maxLength
                   tag:(long)tag
{
	if ([data length] == 0) {
		LogWarn(@"Cannot read: [data length] == 0");
		return;
	}
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	if (maxLength > 0 && maxLength < [data length]) {
		LogWarn(@"Cannot read: maxLength > 0 && maxLength < [data length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:maxLength
	                                                              timeout:timeout
	                                                           readLength:0
	                                                           terminator:data
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (float)progressOfReadReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
	__block float result = 0.0F;
	
	dispatch_block_t block = ^{
		
		if (!currentRead || ![currentRead isKindOfClass:[GCDAsyncReadPacket class]])
		{
			// We're not reading anything right now.
			
			if (tagPtr != NULL)   *tagPtr = 0;
			if (donePtr != NULL)  *donePtr = 0;
			if (totalPtr != NULL) *totalPtr = 0;
			
			result = NAN;
		}
		else
		{
			// It's only possible to know the progress of our read if we're reading to a certain length.
			// If we're reading to data, we of course have no idea when the data will arrive.
			// If we're reading to timeout, then we have no idea when the next chunk of data will arrive.
			
			NSUInteger done = currentRead->bytesDone;
			NSUInteger total = currentRead->readLength;
			
			if (tagPtr != NULL)   *tagPtr = currentRead->tag;
			if (donePtr != NULL)  *donePtr = done;
			if (totalPtr != NULL) *totalPtr = total;
			
			if (total > 0)
				result = (float)done / (float)total;
			else
				result = 1.0F;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

/**
 * This method starts a new read, if needed.
 * 
 * It is called when:
 * - a user requests a read
 * - after a read request has finished (to handle the next request)
 * - immediately after the socket opens to handle any pending requests
 * 
 * This method also handles auto-disconnect post read/write completion.
**/
//让读任务离队   开始执行这条读任务
- (void)maybeDequeueRead
{
	LogTrace();
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	// If we're not currently processing a read AND we have an available read stream
    //如果当前读的包为空，而且 flag 为已连接
	if ((currentRead == nil) && (flags & kConnected))
	{
        //如果读的 queue 大于0 （里面装的使我们封装的 GCDAsyncReadPackage 数据包）
		if ([readQueue count] > 0)
		{
			// Dequeue the next object in the write queue
            //使得下一个对象从写的 queue 中离开
            //从 readQueue 中拿到第一个写的数据
			currentRead = [readQueue objectAtIndex:0];
            //移除
			[readQueue removeObjectAtIndex:0];
			
			//我们的数据包，如果是 GCDAsyncSpecialPacket 这种类型，这个包里装了 TLS 的一些设置
            //如果是这种类型的数据，那么我们就进行 TLS
			if ([currentRead isKindOfClass:[GCDAsyncSpecialPacket class]])
			{
				LogVerbose(@"Dequeued GCDAsyncSpecialPacket");
				
				// Attempt to start TLS
                //标记 flag 为正在读取的 TLS
				flags |= kStartingReadTLS;
				
				// This method won't do anything unless both kStartingReadTLS and kStartingWriteTLS are set
                //只有读写都开启了 TLS，才会做 TLS 认证
				[self maybeStartTLS];
			}
			else
			{
				LogVerbose(@"Dequeued GCDAsyncReadPacket");
				
				// Setup read timer (if needed)
                //设置读的任务超时，每次延时的时候还会调用 doReadData
				[self setupReadTimerWithTimeout:currentRead->timeout];
				
				// Immediately read, if possible
                //读取数据
				[self doReadData];
			}
		}
        //读的队列没有数据，标记 flag 为，读了没有数据则断开连接状态
		else if (flags & kDisconnectAfterReads)
		{
            //如果标记有写然后断开连接
			if (flags & kDisconnectAfterWrites)
			{
                //如果写的队列为0   而且写为空
				if (([writeQueue count] == 0) && (currentWrite == nil))
				{
                    //断开连接
					[self closeWithError:nil];
				}
			}
			else
			{
                //断开连接
				[self closeWithError:nil];
			}
		}
        //如果有安全的 socket
		else if (flags & kSocketSecure)
		{
            
			[self flushSSLBuffers];
			
			// Edge case:
			// 
			// We just drained all data from the ssl buffers,
			// and all known data from the socket (socketFDBytesAvailable).
			// 
			// If we didn't get any data from this process,
			// then we may have reached the end of the TCP stream.
			// 
			// Be sure callbacks are enabled so we're notified about a disconnection.
			//如果可读的字节数为0
			if ([preBuffer availableBytes] == 0)
			{
				if ([self usingCFStreamForTLS]) {
					// Callbacks never disabled
				}
				else {
                    //重新恢复读的 source. 因为每次开始读数据的时候，都会挂起读 desource
					[self resumeReadSource];
				}
			}
		}
	}
}

- (void)flushSSLBuffers
{
	LogTrace();
	
	NSAssert((flags & kSocketSecure), @"Cannot flush ssl buffers on non-secure socket");
	
	if ([preBuffer availableBytes] > 0)
	{
		// Only flush the ssl buffers if the prebuffer is empty.
		// This is to avoid growing the prebuffer inifinitely large.
		
		return;
	}
	
	#if TARGET_OS_IPHONE
	
	if ([self usingCFStreamForTLS])
	{
		if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
		{
			LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
			
			CFIndex defaultBytesToRead = (1024 * 4);
			
			[preBuffer ensureCapacityForWrite:defaultBytesToRead];
			
			uint8_t *buffer = [preBuffer writeBuffer];
			
			CFIndex result = CFReadStreamRead(readStream, buffer, defaultBytesToRead);
			LogVerbose(@"%@ - CFReadStreamRead(): result = %i", THIS_METHOD, (int)result);
			
			if (result > 0)
			{
				[preBuffer didWrite:result];
			}
			
			flags &= ~kSecureSocketHasBytesAvailable;
		}
		
		return;
	}
	
	#endif
	
	__block NSUInteger estimatedBytesAvailable = 0;
	
	dispatch_block_t updateEstimatedBytesAvailable = ^{
		
		// Figure out if there is any data available to be read
		// 
		// socketFDBytesAvailable        <- Number of encrypted bytes we haven't read from the bsd socket
		// [sslPreBuffer availableBytes] <- Number of encrypted bytes we've buffered from bsd socket
		// sslInternalBufSize            <- Number of decrypted bytes SecureTransport has buffered
		// 
		// We call the variable "estimated" because we don't know how many decrypted bytes we'll get
		// from the encrypted bytes in the sslPreBuffer.
		// However, we do know this is an upper bound on the estimation.
		
		estimatedBytesAvailable = socketFDBytesAvailable + [sslPreBuffer availableBytes];
		
		size_t sslInternalBufSize = 0;
		SSLGetBufferedReadSize(sslContext, &sslInternalBufSize);
		
		estimatedBytesAvailable += sslInternalBufSize;
	};
	
	updateEstimatedBytesAvailable();
	
	if (estimatedBytesAvailable > 0)
	{
		LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
		
		BOOL done = NO;
		do
		{
			LogVerbose(@"%@ - estimatedBytesAvailable = %lu", THIS_METHOD, (unsigned long)estimatedBytesAvailable);
			
			// Make sure there's enough room in the prebuffer
			
			[preBuffer ensureCapacityForWrite:estimatedBytesAvailable];
			
			// Read data into prebuffer
			
			uint8_t *buffer = [preBuffer writeBuffer];
			size_t bytesRead = 0;
			
			OSStatus result = SSLRead(sslContext, buffer, (size_t)estimatedBytesAvailable, &bytesRead);
			LogVerbose(@"%@ - read from secure socket = %u", THIS_METHOD, (unsigned)bytesRead);
			
			if (bytesRead > 0)
			{
				[preBuffer didWrite:bytesRead];
			}
			
			LogVerbose(@"%@ - prebuffer.length = %zu", THIS_METHOD, [preBuffer availableBytes]);
			
			if (result != noErr)
			{
				done = YES;
			}
			else
			{
				updateEstimatedBytesAvailable();
			}
			
		} while (!done && estimatedBytesAvailable > 0);
	}
}

- (void)doReadData
{
	LogTrace();
	
	// This method is called on the socketQueue.
	// It might be called directly, or via the readSource when data is available to be read.
	
	if ((currentRead == nil) || (flags & kReadsPaused))
	{
		LogVerbose(@"No currentRead or kReadsPaused");
		
		// Unable to read at this time
		
		if (flags & kSocketSecure)
		{
			// Here's the situation:
			// 
			// We have an established secure connection.
			// There may not be a currentRead, but there might be encrypted data sitting around for us.
			// When the user does get around to issuing a read, that encrypted data will need to be decrypted.
			// 
			// So why make the user wait?
			// We might as well get a head start on decrypting some data now.
			// 
			// The other reason we do this has to do with detecting a socket disconnection.
			// The SSL/TLS protocol has it's own disconnection handshake.
			// So when a secure socket is closed, a "goodbye" packet comes across the wire.
			// We want to make sure we read the "goodbye" packet so we can properly detect the TCP disconnection.
			
			[self flushSSLBuffers];
		}
		
		if ([self usingCFStreamForTLS])
		{
			// CFReadStream only fires once when there is available data.
			// It won't fire again until we've invoked CFReadStreamRead.
		}
		else
		{
			// If the readSource is firing, we need to pause it
			// or else it will continue to fire over and over again.
			// 
			// If the readSource is not firing,
			// we want it to continue monitoring the socket.
			
			if (socketFDBytesAvailable > 0)
			{
				[self suspendReadSource];
			}
		}
		return;
	}
	
	BOOL hasBytesAvailable = NO;
	unsigned long estimatedBytesAvailable = 0;
	
	if ([self usingCFStreamForTLS])
	{
		#if TARGET_OS_IPHONE
		
		// Requested CFStream, rather than SecureTransport, for TLS (via GCDAsyncSocketUseCFStreamForTLS)
		
		estimatedBytesAvailable = 0;
		if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
			hasBytesAvailable = YES;
		else
			hasBytesAvailable = NO;
		
		#endif
	}
	else
	{
		estimatedBytesAvailable = socketFDBytesAvailable;
		
		if (flags & kSocketSecure)
		{
			// There are 2 buffers to be aware of here.
			// 
			// We are using SecureTransport, a TLS/SSL security layer which sits atop TCP.
			// We issue a read to the SecureTranport API, which in turn issues a read to our SSLReadFunction.
			// Our SSLReadFunction then reads from the BSD socket and returns the encrypted data to SecureTransport.
			// SecureTransport then decrypts the data, and finally returns the decrypted data back to us.
			// 
			// The first buffer is one we create.
			// SecureTransport often requests small amounts of data.
			// This has to do with the encypted packets that are coming across the TCP stream.
			// But it's non-optimal to do a bunch of small reads from the BSD socket.
			// So our SSLReadFunction reads all available data from the socket (optimizing the sys call)
			// and may store excess in the sslPreBuffer.
			
			estimatedBytesAvailable += [sslPreBuffer availableBytes];
			
			// The second buffer is within SecureTransport.
			// As mentioned earlier, there are encrypted packets coming across the TCP stream.
			// SecureTransport needs the entire packet to decrypt it.
			// But if the entire packet produces X bytes of decrypted data,
			// and we only asked SecureTransport for X/2 bytes of data,
			// it must store the extra X/2 bytes of decrypted data for the next read.
			// 
			// The SSLGetBufferedReadSize function will tell us the size of this internal buffer.
			// From the documentation:
			// 
			// "This function does not block or cause any low-level read operations to occur."
			
			size_t sslInternalBufSize = 0;
			SSLGetBufferedReadSize(sslContext, &sslInternalBufSize);
			
			estimatedBytesAvailable += sslInternalBufSize;
		}
		
		hasBytesAvailable = (estimatedBytesAvailable > 0);
	}
	
	if ((hasBytesAvailable == NO) && ([preBuffer availableBytes] == 0))
	{
		LogVerbose(@"No data available to read...");
		
		// No data available to read.
		
		if (![self usingCFStreamForTLS])
		{
			// Need to wait for readSource to fire and notify us of
			// available data in the socket's internal read buffer.
			
			[self resumeReadSource];
		}
		return;
	}
	
	if (flags & kStartingReadTLS)
	{
		LogVerbose(@"Waiting for SSL/TLS handshake to complete");
		
		// The readQueue is waiting for SSL/TLS handshake to complete.
		
		if (flags & kStartingWriteTLS)
		{
			if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
			{
				// We are in the process of a SSL Handshake.
				// We were waiting for incoming data which has just arrived.
				
				[self ssl_continueSSLHandshake];
			}
		}
		else
		{
			// We are still waiting for the writeQueue to drain and start the SSL/TLS process.
			// We now know data is available to read.
			
			if (![self usingCFStreamForTLS])
			{
				// Suspend the read source or else it will continue to fire nonstop.
				
				[self suspendReadSource];
			}
		}
		
		return;
	}
	
	BOOL done        = NO;  // Completed read operation
	NSError *error   = nil; // Error occurred
	
	NSUInteger totalBytesReadForCurrentRead = 0;
	
	// 
	// STEP 1 - READ FROM PREBUFFER
	// 
	
	if ([preBuffer availableBytes] > 0)
	{
		// There are 3 types of read packets:
		// 
		// 1) Read all available data.
		// 2) Read a specific length of data.
		// 3) Read up to a particular terminator.
		
		NSUInteger bytesToCopy;
		
		if (currentRead->term != nil)
		{
			// Read type #3 - read up to a terminator
			
			bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
		}
		else
		{
			// Read type #1 or #2
			
			bytesToCopy = [currentRead readLengthForNonTermWithHint:[preBuffer availableBytes]];
		}
		
		// Make sure we have enough room in the buffer for our read.
		
		[currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
		
		// Copy bytes from prebuffer into packet buffer
		
		uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset +
		                                                                  currentRead->bytesDone;
		
		memcpy(buffer, [preBuffer readBuffer], bytesToCopy);
		
		// Remove the copied bytes from the preBuffer
		[preBuffer didRead:bytesToCopy];
		
		LogVerbose(@"copied(%lu) preBufferLength(%zu)", (unsigned long)bytesToCopy, [preBuffer availableBytes]);
		
		// Update totals
		
		currentRead->bytesDone += bytesToCopy;
		totalBytesReadForCurrentRead += bytesToCopy;
		
		// Check to see if the read operation is done
		
		if (currentRead->readLength > 0)
		{
			// Read type #2 - read a specific length of data
			
			done = (currentRead->bytesDone == currentRead->readLength);
		}
		else if (currentRead->term != nil)
		{
			// Read type #3 - read up to a terminator
			
			// Our 'done' variable was updated via the readLengthForTermWithPreBuffer:found: method
			
			if (!done && currentRead->maxLength > 0)
			{
				// We're not done and there's a set maxLength.
				// Have we reached that maxLength yet?
				
				if (currentRead->bytesDone >= currentRead->maxLength)
				{
					error = [self readMaxedOutError];
				}
			}
		}
		else
		{
			// Read type #1 - read all available data
			// 
			// We're done as soon as
			// - we've read all available data (in prebuffer and socket)
			// - we've read the maxLength of read packet.
			
			done = ((currentRead->maxLength > 0) && (currentRead->bytesDone == currentRead->maxLength));
		}
		
	}
	
	// 
	// STEP 2 - READ FROM SOCKET
	// 
	
	BOOL socketEOF = (flags & kSocketHasReadEOF) ? YES : NO;  // Nothing more to read via socket (end of file)
	BOOL waiting   = !done && !error && !socketEOF && !hasBytesAvailable; // Ran out of data, waiting for more
	
	if (!done && !error && !socketEOF && hasBytesAvailable)
	{
		NSAssert(([preBuffer availableBytes] == 0), @"Invalid logic");
		
		BOOL readIntoPreBuffer = NO;
		uint8_t *buffer = NULL;
		size_t bytesRead = 0;
		
		if (flags & kSocketSecure)
		{
			if ([self usingCFStreamForTLS])
			{
				#if TARGET_OS_IPHONE
				
				// Using CFStream, rather than SecureTransport, for TLS
				
				NSUInteger defaultReadLength = (1024 * 32);
				
				NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
				                                                   shouldPreBuffer:&readIntoPreBuffer];
				
				// Make sure we have enough room in the buffer for our read.
				//
				// We are either reading directly into the currentRead->buffer,
				// or we're reading into the temporary preBuffer.
				
				if (readIntoPreBuffer)
				{
					[preBuffer ensureCapacityForWrite:bytesToRead];
					
					buffer = [preBuffer writeBuffer];
				}
				else
				{
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
					
					buffer = (uint8_t *)[currentRead->buffer mutableBytes]
					       + currentRead->startOffset
					       + currentRead->bytesDone;
				}
				
				// Read data into buffer
				
				CFIndex result = CFReadStreamRead(readStream, buffer, (CFIndex)bytesToRead);
				LogVerbose(@"CFReadStreamRead(): result = %i", (int)result);
				
				if (result < 0)
				{
					error = (__bridge_transfer NSError *)CFReadStreamCopyError(readStream);
				}
				else if (result == 0)
				{
					socketEOF = YES;
				}
				else
				{
					waiting = YES;
					bytesRead = (size_t)result;
				}
				
				// We only know how many decrypted bytes were read.
				// The actual number of bytes read was likely more due to the overhead of the encryption.
				// So we reset our flag, and rely on the next callback to alert us of more data.
				flags &= ~kSecureSocketHasBytesAvailable;
				
				#endif
			}
			else
			{
				// Using SecureTransport for TLS
				//
				// We know:
				// - how many bytes are available on the socket
				// - how many encrypted bytes are sitting in the sslPreBuffer
				// - how many decypted bytes are sitting in the sslContext
				//
				// But we do NOT know:
				// - how many encypted bytes are sitting in the sslContext
				//
				// So we play the regular game of using an upper bound instead.
				
				NSUInteger defaultReadLength = (1024 * 32);
				
				if (defaultReadLength < estimatedBytesAvailable) {
					defaultReadLength = estimatedBytesAvailable + (1024 * 16);
				}
				
				NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
				                                                   shouldPreBuffer:&readIntoPreBuffer];
				
				if (bytesToRead > SIZE_MAX) { // NSUInteger may be bigger than size_t
					bytesToRead = SIZE_MAX;
				}
				
				// Make sure we have enough room in the buffer for our read.
				//
				// We are either reading directly into the currentRead->buffer,
				// or we're reading into the temporary preBuffer.
				
				if (readIntoPreBuffer)
				{
					[preBuffer ensureCapacityForWrite:bytesToRead];
					
					buffer = [preBuffer writeBuffer];
				}
				else
				{
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
					
					buffer = (uint8_t *)[currentRead->buffer mutableBytes]
					       + currentRead->startOffset
					       + currentRead->bytesDone;
				}
				
				// The documentation from Apple states:
				// 
				//     "a read operation might return errSSLWouldBlock,
				//      indicating that less data than requested was actually transferred"
				// 
				// However, starting around 10.7, the function will sometimes return noErr,
				// even if it didn't read as much data as requested. So we need to watch out for that.
				
				OSStatus result;
				do
				{
					void *loop_buffer = buffer + bytesRead;
					size_t loop_bytesToRead = (size_t)bytesToRead - bytesRead;
					size_t loop_bytesRead = 0;
					
					result = SSLRead(sslContext, loop_buffer, loop_bytesToRead, &loop_bytesRead);
					LogVerbose(@"read from secure socket = %u", (unsigned)loop_bytesRead);
					
					bytesRead += loop_bytesRead;
					
				} while ((result == noErr) && (bytesRead < bytesToRead));
				
				
				if (result != noErr)
				{
					if (result == errSSLWouldBlock)
						waiting = YES;
					else
					{
						if (result == errSSLClosedGraceful || result == errSSLClosedAbort)
						{
							// We've reached the end of the stream.
							// Handle this the same way we would an EOF from the socket.
							socketEOF = YES;
							sslErrCode = result;
						}
						else
						{
							error = [self sslError:result];
						}
					}
					// It's possible that bytesRead > 0, even if the result was errSSLWouldBlock.
					// This happens when the SSLRead function is able to read some data,
					// but not the entire amount we requested.
					
					if (bytesRead <= 0)
					{
						bytesRead = 0;
					}
				}
				
				// Do not modify socketFDBytesAvailable.
				// It will be updated via the SSLReadFunction().
			}
		}
		else
		{
			// Normal socket operation
			
			NSUInteger bytesToRead;
			
			// There are 3 types of read packets:
			//
			// 1) Read all available data.
			// 2) Read a specific length of data.
			// 3) Read up to a particular terminator.
			
			if (currentRead->term != nil)
			{
				// Read type #3 - read up to a terminator
				
				bytesToRead = [currentRead readLengthForTermWithHint:estimatedBytesAvailable
				                                     shouldPreBuffer:&readIntoPreBuffer];
			}
			else
			{
				// Read type #1 or #2
				
				bytesToRead = [currentRead readLengthForNonTermWithHint:estimatedBytesAvailable];
			}
			
			if (bytesToRead > SIZE_MAX) { // NSUInteger may be bigger than size_t (read param 3)
				bytesToRead = SIZE_MAX;
			}
			
			// Make sure we have enough room in the buffer for our read.
			//
			// We are either reading directly into the currentRead->buffer,
			// or we're reading into the temporary preBuffer.
			
			if (readIntoPreBuffer)
			{
				[preBuffer ensureCapacityForWrite:bytesToRead];
				
				buffer = [preBuffer writeBuffer];
			}
			else
			{
				[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
				
				buffer = (uint8_t *)[currentRead->buffer mutableBytes]
				       + currentRead->startOffset
				       + currentRead->bytesDone;
			}
			
			// Read data into buffer
			
			int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
			
			ssize_t result = read(socketFD, buffer, (size_t)bytesToRead);
			LogVerbose(@"read from socket = %i", (int)result);
			
			if (result < 0)
			{
				if (errno == EWOULDBLOCK)
					waiting = YES;
				else
					error = [self errnoErrorWithReason:@"Error in read() function"];
				
				socketFDBytesAvailable = 0;
			}
			else if (result == 0)
			{
				socketEOF = YES;
				socketFDBytesAvailable = 0;
			}
			else
			{
				bytesRead = result;
				
				if (bytesRead < bytesToRead)
				{
					// The read returned less data than requested.
					// This means socketFDBytesAvailable was a bit off due to timing,
					// because we read from the socket right when the readSource event was firing.
					socketFDBytesAvailable = 0;
				}
				else
				{
					if (socketFDBytesAvailable <= bytesRead)
						socketFDBytesAvailable = 0;
					else
						socketFDBytesAvailable -= bytesRead;
				}
				
				if (socketFDBytesAvailable == 0)
				{
					waiting = YES;
				}
			}
		}
		
		if (bytesRead > 0)
		{
			// Check to see if the read operation is done
			
			if (currentRead->readLength > 0)
			{
				// Read type #2 - read a specific length of data
				// 
				// Note: We should never be using a prebuffer when we're reading a specific length of data.
				
				NSAssert(readIntoPreBuffer == NO, @"Invalid logic");
				
				currentRead->bytesDone += bytesRead;
				totalBytesReadForCurrentRead += bytesRead;
				
				done = (currentRead->bytesDone == currentRead->readLength);
			}
			else if (currentRead->term != nil)
			{
				// Read type #3 - read up to a terminator
				
				if (readIntoPreBuffer)
				{
					// We just read a big chunk of data into the preBuffer
					
					[preBuffer didWrite:bytesRead];
					LogVerbose(@"read data into preBuffer - preBuffer.length = %zu", [preBuffer availableBytes]);
					
					// Search for the terminating sequence
					
					NSUInteger bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
					LogVerbose(@"copying %lu bytes from preBuffer", (unsigned long)bytesToCopy);
					
					// Ensure there's room on the read packet's buffer
					
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
					
					// Copy bytes from prebuffer into read buffer
					
					uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
					                                                                 + currentRead->bytesDone;
					
					memcpy(readBuf, [preBuffer readBuffer], bytesToCopy);
					
					// Remove the copied bytes from the prebuffer
					[preBuffer didRead:bytesToCopy];
					LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
					
					// Update totals
					currentRead->bytesDone += bytesToCopy;
					totalBytesReadForCurrentRead += bytesToCopy;
					
					// Our 'done' variable was updated via the readLengthForTermWithPreBuffer:found: method above
				}
				else
				{
					// We just read a big chunk of data directly into the packet's buffer.
					// We need to move any overflow into the prebuffer.
					
					NSInteger overflow = [currentRead searchForTermAfterPreBuffering:bytesRead];
					
					if (overflow == 0)
					{
						// Perfect match!
						// Every byte we read stays in the read buffer,
						// and the last byte we read was the last byte of the term.
						
						currentRead->bytesDone += bytesRead;
						totalBytesReadForCurrentRead += bytesRead;
						done = YES;
					}
					else if (overflow > 0)
					{
						// The term was found within the data that we read,
						// and there are extra bytes that extend past the end of the term.
						// We need to move these excess bytes out of the read packet and into the prebuffer.
						
						NSInteger underflow = bytesRead - overflow;
						
						// Copy excess data into preBuffer
						
						LogVerbose(@"copying %ld overflow bytes into preBuffer", (long)overflow);
						[preBuffer ensureCapacityForWrite:overflow];
						
						uint8_t *overflowBuffer = buffer + underflow;
						memcpy([preBuffer writeBuffer], overflowBuffer, overflow);
						
						[preBuffer didWrite:overflow];
						LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
						
						// Note: The completeCurrentRead method will trim the buffer for us.
						
						currentRead->bytesDone += underflow;
						totalBytesReadForCurrentRead += underflow;
						done = YES;
					}
					else
					{
						// The term was not found within the data that we read.
						
						currentRead->bytesDone += bytesRead;
						totalBytesReadForCurrentRead += bytesRead;
						done = NO;
					}
				}
				
				if (!done && currentRead->maxLength > 0)
				{
					// We're not done and there's a set maxLength.
					// Have we reached that maxLength yet?
					
					if (currentRead->bytesDone >= currentRead->maxLength)
					{
						error = [self readMaxedOutError];
					}
				}
			}
			else
			{
				// Read type #1 - read all available data
				
				if (readIntoPreBuffer)
				{
					// We just read a chunk of data into the preBuffer
					
					[preBuffer didWrite:bytesRead];
					
					// Now copy the data into the read packet.
					// 
					// Recall that we didn't read directly into the packet's buffer to avoid
					// over-allocating memory since we had no clue how much data was available to be read.
					// 
					// Ensure there's room on the read packet's buffer
					
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesRead];
					
					// Copy bytes from prebuffer into read buffer
					
					uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
					                                                                 + currentRead->bytesDone;
					
					memcpy(readBuf, [preBuffer readBuffer], bytesRead);
					
					// Remove the copied bytes from the prebuffer
					[preBuffer didRead:bytesRead];
					
					// Update totals
					currentRead->bytesDone += bytesRead;
					totalBytesReadForCurrentRead += bytesRead;
				}
				else
				{
					currentRead->bytesDone += bytesRead;
					totalBytesReadForCurrentRead += bytesRead;
				}
				
				done = YES;
			}
			
		} // if (bytesRead > 0)
		
	} // if (!done && !error && !socketEOF && hasBytesAvailable)
	
	
	if (!done && currentRead->readLength == 0 && currentRead->term == nil)
	{
		// Read type #1 - read all available data
		// 
		// We might arrive here if we read data from the prebuffer but not from the socket.
		
		done = (totalBytesReadForCurrentRead > 0);
	}
	
	// Check to see if we're done, or if we've made progress
	
	if (done)
	{
		[self completeCurrentRead];
		
		if (!error && (!socketEOF || [preBuffer availableBytes] > 0))
		{
			[self maybeDequeueRead];
		}
	}
	else if (totalBytesReadForCurrentRead > 0)
	{
		// We're not done read type #2 or #3 yet, but we have read in some bytes

		__strong id theDelegate = delegate;
		
		if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadPartialDataOfLength:tag:)])
		{
			long theReadTag = currentRead->tag;
			
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socket:self didReadPartialDataOfLength:totalBytesReadForCurrentRead tag:theReadTag];
			}});
		}
	}
	
	// Check for errors
	
	if (error)
	{
		[self closeWithError:error];
	}
	else if (socketEOF)
	{
		[self doReadEOF];
	}
	else if (waiting)
	{
		if (![self usingCFStreamForTLS])
		{
			// Monitor the socket for readability (if we're not already doing so)
			[self resumeReadSource];
		}
	}
	
	// Do not add any code here without first adding return statements in the error cases above.
}

- (void)doReadEOF
{
	LogTrace();
	
	// This method may be called more than once.
	// If the EOF is read while there is still data in the preBuffer,
	// then this method may be called continually after invocations of doReadData to see if it's time to disconnect.
	
	flags |= kSocketHasReadEOF;
	
	if (flags & kSocketSecure)
	{
		// If the SSL layer has any buffered data, flush it into the preBuffer now.
		
		[self flushSSLBuffers];
	}
	
	BOOL shouldDisconnect = NO;
	NSError *error = nil;
	
	if ((flags & kStartingReadTLS) || (flags & kStartingWriteTLS))
	{
		// We received an EOF during or prior to startTLS.
		// The SSL/TLS handshake is now impossible, so this is an unrecoverable situation.
		
		shouldDisconnect = YES;
		
		if ([self usingSecureTransportForTLS])
		{
			error = [self sslError:errSSLClosedAbort];
		}
	}
	else if (flags & kReadStreamClosed)
	{
		// The preBuffer has already been drained.
		// The config allows half-duplex connections.
		// We've previously checked the socket, and it appeared writeable.
		// So we marked the read stream as closed and notified the delegate.
		// 
		// As per the half-duplex contract, the socket will be closed when a write fails,
		// or when the socket is manually closed.
		
		shouldDisconnect = NO;
	}
	else if ([preBuffer availableBytes] > 0)
	{
		LogVerbose(@"Socket reached EOF, but there is still data available in prebuffer");
		
		// Although we won't be able to read any more data from the socket,
		// there is existing data that has been prebuffered that we can read.
		
		shouldDisconnect = NO;
	}
	else if (config & kAllowHalfDuplexConnection)
	{
		// We just received an EOF (end of file) from the socket's read stream.
		// This means the remote end of the socket (the peer we're connected to)
		// has explicitly stated that it will not be sending us any more data.
		// 
		// Query the socket to see if it is still writeable. (Perhaps the peer will continue reading data from us)
		
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
		struct pollfd pfd[1];
		pfd[0].fd = socketFD;
		pfd[0].events = POLLOUT;
		pfd[0].revents = 0;
		
		poll(pfd, 1, 0);
		
		if (pfd[0].revents & POLLOUT)
		{
			// Socket appears to still be writeable
			
			shouldDisconnect = NO;
			flags |= kReadStreamClosed;
			
			// Notify the delegate that we're going half-duplex
			
			__strong id theDelegate = delegate;

			if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidCloseReadStream:)])
			{
				dispatch_async(delegateQueue, ^{ @autoreleasepool {
					
					[theDelegate socketDidCloseReadStream:self];
				}});
			}
		}
		else
		{
			shouldDisconnect = YES;
		}
	}
	else
	{
		shouldDisconnect = YES;
	}
	
	
	if (shouldDisconnect)
	{
		if (error == nil)
		{
			if ([self usingSecureTransportForTLS])
			{
				if (sslErrCode != noErr && sslErrCode != errSSLClosedGraceful)
				{
					error = [self sslError:sslErrCode];
				}
				else
				{
					error = [self connectionClosedError];
				}
			}
			else
			{
				error = [self connectionClosedError];
			}
		}
		[self closeWithError:error];
	}
	else
	{
		if (![self usingCFStreamForTLS])
		{
			// Suspend the read source (if needed)
			
			[self suspendReadSource];
		}
	}
}

- (void)completeCurrentRead
{
	LogTrace();
	
	NSAssert(currentRead, @"Trying to complete current read when there is no current read.");
	
	
	NSData *result = nil;
	
	if (currentRead->bufferOwner)
	{
		// We created the buffer on behalf of the user.
		// Trim our buffer to be the proper size.
		[currentRead->buffer setLength:currentRead->bytesDone];
		
		result = currentRead->buffer;
	}
	else
	{
		// We did NOT create the buffer.
		// The buffer is owned by the caller.
		// Only trim the buffer if we had to increase its size.
		
		if ([currentRead->buffer length] > currentRead->originalBufferLength)
		{
			NSUInteger readSize = currentRead->startOffset + currentRead->bytesDone;
			NSUInteger origSize = currentRead->originalBufferLength;
			
			NSUInteger buffSize = MAX(readSize, origSize);
			
			[currentRead->buffer setLength:buffSize];
		}
		
		uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset;
		
		result = [NSData dataWithBytesNoCopy:buffer length:currentRead->bytesDone freeWhenDone:NO];
	}
	
	__strong id theDelegate = delegate;

	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadData:withTag:)])
	{
		GCDAsyncReadPacket *theRead = currentRead; // Ensure currentRead retained since result may not own buffer
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			[theDelegate socket:self didReadData:result withTag:theRead->tag];
		}});
	}
	
	[self endCurrentRead];
}

- (void)endCurrentRead
{
	if (readTimer)
	{
		dispatch_source_cancel(readTimer);
		readTimer = NULL;
	}
	
	currentRead = nil;
}

- (void)setupReadTimerWithTimeout:(NSTimeInterval)timeout
{
	if (timeout >= 0.0)
	{
		readTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
		dispatch_source_set_event_handler(readTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			
			[strongSelf doReadTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
		dispatch_source_t theReadTimer = readTimer;
		dispatch_source_set_cancel_handler(readTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(readTimer)");
			dispatch_release(theReadTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
		
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
		
		dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
		dispatch_resume(readTimer);
	}
}

- (void)doReadTimeout
{
	// This is a little bit tricky.
	// Ideally we'd like to synchronously query the delegate about a timeout extension.
	// But if we do so synchronously we risk a possible deadlock.
	// So instead we have to do so asynchronously, and callback to ourselves from within the delegate block.
	
	flags |= kReadsPaused;
	
	__strong id theDelegate = delegate;

	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutReadWithTag:elapsed:bytesDone:)])
	{
		GCDAsyncReadPacket *theRead = currentRead;
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			NSTimeInterval timeoutExtension = 0.0;
			
			timeoutExtension = [theDelegate socket:self shouldTimeoutReadWithTag:theRead->tag
			                                                             elapsed:theRead->timeout
			                                                           bytesDone:theRead->bytesDone];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self doReadTimeoutWithExtension:timeoutExtension];
			}});
		}});
	}
	else
	{
		[self doReadTimeoutWithExtension:0.0];
	}
}

- (void)doReadTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
	if (currentRead)
	{
		if (timeoutExtension > 0.0)
		{
			currentRead->timeout += timeoutExtension;
			
			// Reschedule the timer
			dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
			dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
			
			// Unpause reads, and continue
			flags &= ~kReadsPaused;
			[self doReadData];
		}
		else
		{
			LogVerbose(@"ReadTimeout");
			
			[self closeWithError:[self readTimeoutError]];
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Writing
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	if ([data length] == 0) return;
	
	GCDAsyncWritePacket *packet = [[GCDAsyncWritePacket alloc] initWithData:data timeout:timeout tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
			[writeQueue addObject:packet];
			[self maybeDequeueWrite];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (float)progressOfWriteReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
	__block float result = 0.0F;
	
	dispatch_block_t block = ^{
		
		if (!currentWrite || ![currentWrite isKindOfClass:[GCDAsyncWritePacket class]])
		{
			// We're not writing anything right now.
			
			if (tagPtr != NULL)   *tagPtr = 0;
			if (donePtr != NULL)  *donePtr = 0;
			if (totalPtr != NULL) *totalPtr = 0;
			
			result = NAN;
		}
		else
		{
			NSUInteger done = currentWrite->bytesDone;
			NSUInteger total = [currentWrite->buffer length];
			
			if (tagPtr != NULL)   *tagPtr = currentWrite->tag;
			if (donePtr != NULL)  *donePtr = done;
			if (totalPtr != NULL) *totalPtr = total;
			
			result = (float)done / (float)total;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

/**
 * Conditionally starts a new write.
 * 
 * It is called when:
 * - a user requests a write
 * - after a write request has finished (to handle the next request)
 * - immediately after the socket opens to handle any pending requests
 * 
 * This method also handles auto-disconnect post read/write completion.
**/
- (void)maybeDequeueWrite
{
	LogTrace();
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	
	// If we're not currently processing a write AND we have an available write stream
	if ((currentWrite == nil) && (flags & kConnected))
	{
		if ([writeQueue count] > 0)
		{
			// Dequeue the next object in the write queue
			currentWrite = [writeQueue objectAtIndex:0];
			[writeQueue removeObjectAtIndex:0];
			
			
			if ([currentWrite isKindOfClass:[GCDAsyncSpecialPacket class]])
			{
				LogVerbose(@"Dequeued GCDAsyncSpecialPacket");
				
				// Attempt to start TLS
				flags |= kStartingWriteTLS;
				
				// This method won't do anything unless both kStartingReadTLS and kStartingWriteTLS are set
				[self maybeStartTLS];
			}
			else
			{
				LogVerbose(@"Dequeued GCDAsyncWritePacket");
				
				// Setup write timer (if needed)
				[self setupWriteTimerWithTimeout:currentWrite->timeout];
				
				// Immediately write, if possible
				[self doWriteData];
			}
		}
		else if (flags & kDisconnectAfterWrites)
		{
			if (flags & kDisconnectAfterReads)
			{
				if (([readQueue count] == 0) && (currentRead == nil))
				{
					[self closeWithError:nil];
				}
			}
			else
			{
				[self closeWithError:nil];
			}
		}
	}
}

- (void)doWriteData
{
	LogTrace();
	
	// This method is called by the writeSource via the socketQueue
	
	if ((currentWrite == nil) || (flags & kWritesPaused))
	{
		LogVerbose(@"No currentWrite or kWritesPaused");
		
		// Unable to write at this time
		
		if ([self usingCFStreamForTLS])
		{
			// CFWriteStream only fires once when there is available data.
			// It won't fire again until we've invoked CFWriteStreamWrite.
		}
		else
		{
			// If the writeSource is firing, we need to pause it
			// or else it will continue to fire over and over again.
			
			if (flags & kSocketCanAcceptBytes)
			{
				[self suspendWriteSource];
			}
		}
		return;
	}
	
	if (!(flags & kSocketCanAcceptBytes))
	{
		LogVerbose(@"No space available to write...");
		
		// No space available to write.
		
		if (![self usingCFStreamForTLS])
		{
			// Need to wait for writeSource to fire and notify us of
			// available space in the socket's internal write buffer.
			
			[self resumeWriteSource];
		}
		return;
	}
	
	if (flags & kStartingWriteTLS)
	{
		LogVerbose(@"Waiting for SSL/TLS handshake to complete");
		
		// The writeQueue is waiting for SSL/TLS handshake to complete.
		
		if (flags & kStartingReadTLS)
		{
			if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
			{
				// We are in the process of a SSL Handshake.
				// We were waiting for available space in the socket's internal OS buffer to continue writing.
			
				[self ssl_continueSSLHandshake];
			}
		}
		else
		{
			// We are still waiting for the readQueue to drain and start the SSL/TLS process.
			// We now know we can write to the socket.
			
			if (![self usingCFStreamForTLS])
			{
				// Suspend the write source or else it will continue to fire nonstop.
				
				[self suspendWriteSource];
			}
		}
		
		return;
	}
	
	// Note: This method is not called if currentWrite is a GCDAsyncSpecialPacket (startTLS packet)
	
	BOOL waiting = NO;
	NSError *error = nil;
	size_t bytesWritten = 0;
	
	if (flags & kSocketSecure)
	{
		if ([self usingCFStreamForTLS])
		{
			#if TARGET_OS_IPHONE
			
			// 
			// Writing data using CFStream (over internal TLS)
			// 
			
			const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
			
			NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
			
			if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
			{
				bytesToWrite = SIZE_MAX;
			}
		
			CFIndex result = CFWriteStreamWrite(writeStream, buffer, (CFIndex)bytesToWrite);
			LogVerbose(@"CFWriteStreamWrite(%lu) = %li", (unsigned long)bytesToWrite, result);
		
			if (result < 0)
			{
				error = (__bridge_transfer NSError *)CFWriteStreamCopyError(writeStream);
			}
			else
			{
				bytesWritten = (size_t)result;
				
				// We always set waiting to true in this scenario.
				// CFStream may have altered our underlying socket to non-blocking.
				// Thus if we attempt to write without a callback, we may end up blocking our queue.
				waiting = YES;
			}
			
			#endif
		}
		else
		{
			// We're going to use the SSLWrite function.
			// 
			// OSStatus SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed)
			// 
			// Parameters:
			// context     - An SSL session context reference.
			// data        - A pointer to the buffer of data to write.
			// dataLength  - The amount, in bytes, of data to write.
			// processed   - On return, the length, in bytes, of the data actually written.
			// 
			// It sounds pretty straight-forward,
			// but there are a few caveats you should be aware of.
			// 
			// The SSLWrite method operates in a non-obvious (and rather annoying) manner.
			// According to the documentation:
			// 
			//   Because you may configure the underlying connection to operate in a non-blocking manner,
			//   a write operation might return errSSLWouldBlock, indicating that less data than requested
			//   was actually transferred. In this case, you should repeat the call to SSLWrite until some
			//   other result is returned.
			// 
			// This sounds perfect, but when our SSLWriteFunction returns errSSLWouldBlock,
			// then the SSLWrite method returns (with the proper errSSLWouldBlock return value),
			// but it sets processed to dataLength !!
			// 
			// In other words, if the SSLWrite function doesn't completely write all the data we tell it to,
			// then it doesn't tell us how many bytes were actually written. So, for example, if we tell it to
			// write 256 bytes then it might actually write 128 bytes, but then report 0 bytes written.
			// 
			// You might be wondering:
			// If the SSLWrite function doesn't tell us how many bytes were written,
			// then how in the world are we supposed to update our parameters (buffer & bytesToWrite)
			// for the next time we invoke SSLWrite?
			// 
			// The answer is that SSLWrite cached all the data we told it to write,
			// and it will push out that data next time we call SSLWrite.
			// If we call SSLWrite with new data, it will push out the cached data first, and then the new data.
			// If we call SSLWrite with empty data, then it will simply push out the cached data.
			// 
			// For this purpose we're going to break large writes into a series of smaller writes.
			// This allows us to report progress back to the delegate.
			
			OSStatus result;
			
			BOOL hasCachedDataToWrite = (sslWriteCachedLength > 0);
			BOOL hasNewDataToWrite = YES;
			
			if (hasCachedDataToWrite)
			{
				size_t processed = 0;
				
				result = SSLWrite(sslContext, NULL, 0, &processed);
				
				if (result == noErr)
				{
					bytesWritten = sslWriteCachedLength;
					sslWriteCachedLength = 0;
					
					if ([currentWrite->buffer length] == (currentWrite->bytesDone + bytesWritten))
					{
						// We've written all data for the current write.
						hasNewDataToWrite = NO;
					}
				}
				else
				{
					if (result == errSSLWouldBlock)
					{
						waiting = YES;
					}
					else
					{
						error = [self sslError:result];
					}
					
					// Can't write any new data since we were unable to write the cached data.
					hasNewDataToWrite = NO;
				}
			}
			
			if (hasNewDataToWrite)
			{
				const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes]
				                                        + currentWrite->bytesDone
				                                        + bytesWritten;
				
				NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone - bytesWritten;
				
				if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
				{
					bytesToWrite = SIZE_MAX;
				}
				
				size_t bytesRemaining = bytesToWrite;
				
				BOOL keepLooping = YES;
				while (keepLooping)
				{
					const size_t sslMaxBytesToWrite = 32768;
					size_t sslBytesToWrite = MIN(bytesRemaining, sslMaxBytesToWrite);
					size_t sslBytesWritten = 0;
					
					result = SSLWrite(sslContext, buffer, sslBytesToWrite, &sslBytesWritten);
					
					if (result == noErr)
					{
						buffer += sslBytesWritten;
						bytesWritten += sslBytesWritten;
						bytesRemaining -= sslBytesWritten;
						
						keepLooping = (bytesRemaining > 0);
					}
					else
					{
						if (result == errSSLWouldBlock)
						{
							waiting = YES;
							sslWriteCachedLength = sslBytesToWrite;
						}
						else
						{
							error = [self sslError:result];
						}
						
						keepLooping = NO;
					}
					
				} // while (keepLooping)
				
			} // if (hasNewDataToWrite)
		}
	}
	else
	{
		// 
		// Writing data directly over raw socket
		// 
		
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
		const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
		
		NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
		
		if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
		{
			bytesToWrite = SIZE_MAX;
		}
		
		ssize_t result = write(socketFD, buffer, (size_t)bytesToWrite);
		LogVerbose(@"wrote to socket = %zd", result);
		
		// Check results
		if (result < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				waiting = YES;
			}
			else
			{
				error = [self errnoErrorWithReason:@"Error in write() function"];
			}
		}
		else
		{
			bytesWritten = result;
		}
	}
	
	// We're done with our writing.
	// If we explictly ran into a situation where the socket told us there was no room in the buffer,
	// then we immediately resume listening for notifications.
	// 
	// We must do this before we dequeue another write,
	// as that may in turn invoke this method again.
	// 
	// Note that if CFStream is involved, it may have maliciously put our socket in blocking mode.
	
	if (waiting)
	{
		flags &= ~kSocketCanAcceptBytes;
		
		if (![self usingCFStreamForTLS])
		{
			[self resumeWriteSource];
		}
	}
	
	// Check our results
	
	BOOL done = NO;
	
	if (bytesWritten > 0)
	{
		// Update total amount read for the current write
		currentWrite->bytesDone += bytesWritten;
		LogVerbose(@"currentWrite->bytesDone = %lu", (unsigned long)currentWrite->bytesDone);
		
		// Is packet done?
		done = (currentWrite->bytesDone == [currentWrite->buffer length]);
	}
	
	if (done)
	{
		[self completeCurrentWrite];
		
		if (!error)
		{
			dispatch_async(socketQueue, ^{ @autoreleasepool{
				
				[self maybeDequeueWrite];
			}});
		}
	}
	else
	{
		// We were unable to finish writing the data,
		// so we're waiting for another callback to notify us of available space in the lower-level output buffer.
		
		if (!waiting && !error)
		{
			// This would be the case if our write was able to accept some data, but not all of it.
			
			flags &= ~kSocketCanAcceptBytes;
			
			if (![self usingCFStreamForTLS])
			{
				[self resumeWriteSource];
			}
		}
		
		if (bytesWritten > 0)
		{
			// We're not done with the entire write, but we have written some bytes
			
			__strong id theDelegate = delegate;

			if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWritePartialDataOfLength:tag:)])
			{
				long theWriteTag = currentWrite->tag;
				
				dispatch_async(delegateQueue, ^{ @autoreleasepool {
					
					[theDelegate socket:self didWritePartialDataOfLength:bytesWritten tag:theWriteTag];
				}});
			}
		}
	}
	
	// Check for errors
	
	if (error)
	{
		[self closeWithError:[self errnoErrorWithReason:@"Error in write() function"]];
	}
	
	// Do not add any code here without first adding a return statement in the error case above.
}

- (void)completeCurrentWrite
{
	LogTrace();
	
	NSAssert(currentWrite, @"Trying to complete current write when there is no current write.");
	

	__strong id theDelegate = delegate;
	
	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWriteDataWithTag:)])
	{
		long theWriteTag = currentWrite->tag;
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			[theDelegate socket:self didWriteDataWithTag:theWriteTag];
		}});
	}
	
	[self endCurrentWrite];
}

- (void)endCurrentWrite
{
	if (writeTimer)
	{
		dispatch_source_cancel(writeTimer);
		writeTimer = NULL;
	}
	
	currentWrite = nil;
}

- (void)setupWriteTimerWithTimeout:(NSTimeInterval)timeout
{
	if (timeout >= 0.0)
	{
		writeTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
		dispatch_source_set_event_handler(writeTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			
			[strongSelf doWriteTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
		dispatch_source_t theWriteTimer = writeTimer;
		dispatch_source_set_cancel_handler(writeTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(writeTimer)");
			dispatch_release(theWriteTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
		
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
		
		dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
		dispatch_resume(writeTimer);
	}
}

- (void)doWriteTimeout
{
	// This is a little bit tricky.
	// Ideally we'd like to synchronously query the delegate about a timeout extension.
	// But if we do so synchronously we risk a possible deadlock.
	// So instead we have to do so asynchronously, and callback to ourselves from within the delegate block.
	
	flags |= kWritesPaused;
	
	__strong id theDelegate = delegate;

	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutWriteWithTag:elapsed:bytesDone:)])
	{
		GCDAsyncWritePacket *theWrite = currentWrite;
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			NSTimeInterval timeoutExtension = 0.0;
			
			timeoutExtension = [theDelegate socket:self shouldTimeoutWriteWithTag:theWrite->tag
			                                                              elapsed:theWrite->timeout
			                                                            bytesDone:theWrite->bytesDone];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self doWriteTimeoutWithExtension:timeoutExtension];
			}});
		}});
	}
	else
	{
		[self doWriteTimeoutWithExtension:0.0];
	}
}

- (void)doWriteTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
	if (currentWrite)
	{
		if (timeoutExtension > 0.0)
		{
			currentWrite->timeout += timeoutExtension;
			
			// Reschedule the timer
			dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
			dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
			
			// Unpause writes, and continue
			flags &= ~kWritesPaused;
			[self doWriteData];
		}
		else
		{
			LogVerbose(@"WriteTimeout");
			
			[self closeWithError:[self writeTimeoutError]];
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//开启 TLS
- (void)startTLS:(NSDictionary *)tlsSettings
{
	LogTrace();
	
	if (tlsSettings == nil)
    {
        // Passing nil/NULL to CFReadStreamSetProperty will appear to work the same as passing an empty dictionary,
        // but causes problems if we later try to fetch the remote host's certificate.
        // 
        // To be exact, it causes the following to return NULL instead of the normal result:
        // CFReadStreamCopyProperty(readStream, kCFStreamPropertySSLPeerCertificates)
        // 
        // So we use an empty dictionary instead, which works perfectly.
        
        tlsSettings = [NSDictionary dictionary];
    }
	
    //新生成一个 TLS 特殊的包
	GCDAsyncSpecialPacket *packet = [[GCDAsyncSpecialPacket alloc] initWithTLSSettings:tlsSettings];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if ((flags & kSocketStarted) && !(flags & kQueuedTLS) && !(flags & kForbidReadsWrites))
		{
            //添加到读写 Queue 去
			[readQueue addObject:packet];
			[writeQueue addObject:packet];
			
            //把 TLS 标记加上
			flags |= kQueuedTLS;
			
            //开始读取 TLS 的任务， 读到这个包会做 TLS 认证， 在这之前的包还是不用认证就可以传送完
			[self maybeDequeueRead];
			[self maybeDequeueWrite];
		}
	}});
	
}

//可能开启 TLS
- (void)maybeStartTLS
{
	// We can't start TLS until:
	// - All queued reads prior to the user calling startTLS are complete
	// - All queued writes prior to the user calling startTLS are complete
	// 
	// We'll know these conditions are met when both kStartingReadTLS and kStartingWriteTLS are set
	
    //只有读和写 TLS 都开启
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
        //需要安全传输
		BOOL useSecureTransport = YES;
		
		#if TARGET_OS_IPHONE
		{
            //拿到当前读的数据
			GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
            //得到设置字典
            NSDictionary *tlsSettings = @{};
            if (tlsPacket) {
                tlsSettings = tlsPacket->tlsSettings;
            }
            //拿到 key 为 CFStreamTLS的 value
			NSNumber *value = [tlsSettings objectForKey:GCDAsyncSocketUseCFStreamForTLS];
			if (value && [value boolValue])
                //如果是用 CFStream 的， 则安全传输为 NO
				useSecureTransport = NO;
		}
		#endif
		
        
        //如果使用安全通道
		if (useSecureTransport)
		{
            //开启 TLS
			[self ssl_startTLS];
		}
        //CFStream 形式的 TLS
		else
		{
		#if TARGET_OS_IPHONE
			[self cf_startTLS];
		#endif
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via SecureTransport
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (OSStatus)sslReadWithBuffer:(void *)buffer length:(size_t *)bufferLength
{
	LogVerbose(@"sslReadWithBuffer:%p length:%lu", buffer, (unsigned long)*bufferLength);
	
	if ((socketFDBytesAvailable == 0) && ([sslPreBuffer availableBytes] == 0))
	{
		LogVerbose(@"%@ - No data available to read...", THIS_METHOD);
		
		// No data available to read.
		// 
		// Need to wait for readSource to fire and notify us of
		// available data in the socket's internal read buffer.
		
		[self resumeReadSource];
		
		*bufferLength = 0;
		return errSSLWouldBlock;
	}
	
	size_t totalBytesRead = 0;
	size_t totalBytesLeftToBeRead = *bufferLength;
	
	BOOL done = NO;
	BOOL socketError = NO;
	
	// 
	// STEP 1 : READ FROM SSL PRE BUFFER
	// 
	
	size_t sslPreBufferLength = [sslPreBuffer availableBytes];
	
	if (sslPreBufferLength > 0)
	{
		LogVerbose(@"%@: Reading from SSL pre buffer...", THIS_METHOD);
		
		size_t bytesToCopy;
		if (sslPreBufferLength > totalBytesLeftToBeRead)
			bytesToCopy = totalBytesLeftToBeRead;
		else
			bytesToCopy = sslPreBufferLength;
		
		LogVerbose(@"%@: Copying %zu bytes from sslPreBuffer", THIS_METHOD, bytesToCopy);
		
		memcpy(buffer, [sslPreBuffer readBuffer], bytesToCopy);
		[sslPreBuffer didRead:bytesToCopy];
		
		LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
		
		totalBytesRead += bytesToCopy;
		totalBytesLeftToBeRead -= bytesToCopy;
		
		done = (totalBytesLeftToBeRead == 0);
		
		if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
	}
	
	// 
	// STEP 2 : READ FROM SOCKET
	// 
	
	if (!done && (socketFDBytesAvailable > 0))
	{
		LogVerbose(@"%@: Reading from socket...", THIS_METHOD);
		
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
		BOOL readIntoPreBuffer;
		size_t bytesToRead;
		uint8_t *buf;
		
		if (socketFDBytesAvailable > totalBytesLeftToBeRead)
		{
			// Read all available data from socket into sslPreBuffer.
			// Then copy requested amount into dataBuffer.
			
			LogVerbose(@"%@: Reading into sslPreBuffer...", THIS_METHOD);
			
			[sslPreBuffer ensureCapacityForWrite:socketFDBytesAvailable];
			
			readIntoPreBuffer = YES;
			bytesToRead = (size_t)socketFDBytesAvailable;
			buf = [sslPreBuffer writeBuffer];
		}
		else
		{
			// Read available data from socket directly into dataBuffer.
			
			LogVerbose(@"%@: Reading directly into dataBuffer...", THIS_METHOD);
			
			readIntoPreBuffer = NO;
			bytesToRead = totalBytesLeftToBeRead;
			buf = (uint8_t *)buffer + totalBytesRead;
		}
		
		ssize_t result = read(socketFD, buf, bytesToRead);
		LogVerbose(@"%@: read from socket = %zd", THIS_METHOD, result);
		
		if (result < 0)
		{
			LogVerbose(@"%@: read errno = %i", THIS_METHOD, errno);
			
			if (errno != EWOULDBLOCK)
			{
				socketError = YES;
			}
			
			socketFDBytesAvailable = 0;
		}
		else if (result == 0)
		{
			LogVerbose(@"%@: read EOF", THIS_METHOD);
			
			socketError = YES;
			socketFDBytesAvailable = 0;
		}
		else
		{
			size_t bytesReadFromSocket = result;
			
			if (socketFDBytesAvailable > bytesReadFromSocket)
				socketFDBytesAvailable -= bytesReadFromSocket;
			else
				socketFDBytesAvailable = 0;
			
			if (readIntoPreBuffer)
			{
				[sslPreBuffer didWrite:bytesReadFromSocket];
				
				size_t bytesToCopy = MIN(totalBytesLeftToBeRead, bytesReadFromSocket);
				
				LogVerbose(@"%@: Copying %zu bytes out of sslPreBuffer", THIS_METHOD, bytesToCopy);
				
				memcpy((uint8_t *)buffer + totalBytesRead, [sslPreBuffer readBuffer], bytesToCopy);
				[sslPreBuffer didRead:bytesToCopy];
				
				totalBytesRead += bytesToCopy;
				totalBytesLeftToBeRead -= bytesToCopy;
				
				LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
			}
			else
			{
				totalBytesRead += bytesReadFromSocket;
				totalBytesLeftToBeRead -= bytesReadFromSocket;
			}
			
			done = (totalBytesLeftToBeRead == 0);
			
			if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
		}
	}
	
	*bufferLength = totalBytesRead;
	
	if (done)
		return noErr;
	
	if (socketError)
		return errSSLClosedAbort;
	
	return errSSLWouldBlock;
}

- (OSStatus)sslWriteWithBuffer:(const void *)buffer length:(size_t *)bufferLength
{
	if (!(flags & kSocketCanAcceptBytes))
	{
		// Unable to write.
		// 
		// Need to wait for writeSource to fire and notify us of
		// available space in the socket's internal write buffer.
		
		[self resumeWriteSource];
		
		*bufferLength = 0;
		return errSSLWouldBlock;
	}
	
	size_t bytesToWrite = *bufferLength;
	size_t bytesWritten = 0;
	
	BOOL done = NO;
	BOOL socketError = NO;
	
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	
	ssize_t result = write(socketFD, buffer, bytesToWrite);
	
	if (result < 0)
	{
		if (errno != EWOULDBLOCK)
		{
			socketError = YES;
		}
		
		flags &= ~kSocketCanAcceptBytes;
	}
	else if (result == 0)
	{
		flags &= ~kSocketCanAcceptBytes;
	}
	else
	{
		bytesWritten = result;
		
		done = (bytesWritten == bytesToWrite);
	}
	
	*bufferLength = bytesWritten;
	
	if (done)
		return noErr;
	
	if (socketError)
		return errSSLClosedAbort;
	
	return errSSLWouldBlock;
}

//读函数
static OSStatus SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    //拿到 socket
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)connection;
	
    //断言当前为 socketQueue
	NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
	
    //读取数据并且返回状态吗
	return [asyncSocket sslReadWithBuffer:data length:dataLength];
}

//写函数
static OSStatus SSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)connection;
	
	NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
	
	return [asyncSocket sslWriteWithBuffer:data length:dataLength];
}


//开启 TLS
- (void)ssl_startTLS
{
	LogTrace();
	
	LogVerbose(@"Starting TLS (via SecureTransport)...");
	
    //状态标记
	OSStatus status;
	
    //拿到当前读的数据包
	GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
	if (tlsPacket == nil) // Code to quiet the analyzer
	{
		NSAssert(NO, @"Logic error");
		
		[self closeWithError:[self otherError:@"Logic error"]];
		return;
	}
    //拿到设置
	NSDictionary *tlsSettings = tlsPacket->tlsSettings;
	
	// Create SSLContext, and setup IO callbacks and connection ref
	//根据 key 来判断，当前包是否是服务端的
	BOOL isServer = [[tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLIsServer] boolValue];
	
    //创建 SSL 上下文
	#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
	{
        //如果是服务端的创建服务端上下文，否则是客户端的上下文，用 stream 形式
		if (isServer)
			sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
		else
			sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
		
        //为空则报错返回
		if (sslContext == NULL)
		{
			[self closeWithError:[self otherError:@"Error in SSLCreateContext"]];
			return;
		}
	}
	#else // (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
	{
		status = SSLNewContext(isServer, &sslContext);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLNewContext"]];
			return;
		}
	}
	#endif
	
    //给 SSL 上下文设置 IO 回调， 分别为 SSL 读写函数
	status = SSLSetIOFuncs(sslContext, &SSLReadFunction, &SSLWriteFunction);
    //设置出错
	if (status != noErr)
	{
		[self closeWithError:[self otherError:@"Error in SSLSetIOFuncs"]];
		return;
	}
	
    //在我手之前调用，建立 SSL 连接，第一次连接1
	status = SSLSetConnection(sslContext, (__bridge SSLConnectionRef)self);
    //连接出错
	if (status != noErr)
	{
		[self closeWithError:[self otherError:@"Error in SSLSetConnection"]];
		return;
	}

    //是否应该手动去信任
	BOOL shouldManuallyEvaluateTrust = [[tlsSettings objectForKey:GCDAsyncSocketManuallyEvaluateTrust] boolValue];
	if (shouldManuallyEvaluateTrust)
	{
        //是服务端的话，不需要，报错返回
		if (isServer)
		{
			[self closeWithError:[self otherError:@"Manual trust validation is not supported for server sockets"]];
			return;
		}
		
        //第二次连接，再去连接用kSSLSessionOptionBreakOnServerAuth的方式，去连接一次，这种方式可以直接信任服务端证书
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
        //错误直接返回
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetSessionOption"]];
			return;
		}
		
		#if !TARGET_OS_IPHONE && (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
		
		// Note from Apple's documentation:
		//
		// It is only necessary to call SSLSetEnableCertVerify on the Mac prior to OS X 10.8.
		// On OS X 10.8 and later setting kSSLSessionOptionBreakOnServerAuth always disables the
		// built-in trust evaluation. All versions of iOS behave like OS X 10.8 and thus
		// SSLSetEnableCertVerify is not available on that platform at all.
		
        //为了防止 kSSLSessionOptionBreakOnServerAuth 这种情况下，产生了不受信任的环境
		status = SSLSetEnableCertVerify(sslContext, NO);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetEnableCertVerify"]];
			return;
		}
		
		#endif
	}

	// Configure SSLContext from given settings
	// 
	// Checklist:
	//  1. kCFStreamSSLPeerName
	//  2. kCFStreamSSLCertificates
	//  3. GCDAsyncSocketSSLPeerID
	//  4. GCDAsyncSocketSSLProtocolVersionMin
	//  5. GCDAsyncSocketSSLProtocolVersionMax
	//  6. GCDAsyncSocketSSLSessionOptionFalseStart
	//  7. GCDAsyncSocketSSLSessionOptionSendOneByteRecord
	//  8. GCDAsyncSocketSSLCipherSuites
	//  9. GCDAsyncSocketSSLDiffieHellmanParameters (Mac)
	//
	// Deprecated (throw error):
	// 10. kCFStreamSSLAllowsAnyRoot
	// 11. kCFStreamSSLAllowsExpiredRoots
	// 12. kCFStreamSSLAllowsExpiredCertificates
	// 13. kCFStreamSSLValidatesCertificateChain
	// 14. kCFStreamSSLLevel
    
    //配置 SSL 上下文设置
	
	id value;
	
    //这个参数是用来获取证书名验证，如果设置为 NULL，则不验证
	// 1. kCFStreamSSLPeerName
	
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLPeerName];
	if ([value isKindOfClass:[NSString class]])
	{
		NSString *peerName = (NSString *)value;
		
		const char *peer = [peerName UTF8String];
		size_t peerLen = strlen(peer);
		
        //把证书名设置给 SSL
		status = SSLSetPeerDomainName(sslContext, peer, peerLen);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetPeerDomainName"]];
			return;
		}
	}
    //不是 string 就错误返回
	else if (value)
	{
		NSAssert(NO, @"Invalid value for kCFStreamSSLPeerName. Value must be of type NSString.");
		
		[self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLPeerName."]];
		return;
	}
	
	// 2. kCFStreamSSLCertificates
	
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLCertificates];
	if ([value isKindOfClass:[NSArray class]])
	{
		CFArrayRef certs = (__bridge CFArrayRef)value;
		
		status = SSLSetCertificate(sslContext, certs);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetCertificate"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for kCFStreamSSLCertificates. Value must be of type NSArray.");
		
		[self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLCertificates."]];
		return;
	}
	
	// 3. GCDAsyncSocketSSLPeerID
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLPeerID];
	if ([value isKindOfClass:[NSData class]])
	{
		NSData *peerIdData = (NSData *)value;
		
		status = SSLSetPeerID(sslContext, [peerIdData bytes], [peerIdData length]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetPeerID"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLPeerID. Value must be of type NSData."
		             @" (You can convert strings to data using a method like"
		             @" [string dataUsingEncoding:NSUTF8StringEncoding])");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLPeerID."]];
		return;
	}
	
	// 4. GCDAsyncSocketSSLProtocolVersionMin
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLProtocolVersionMin];
	if ([value isKindOfClass:[NSNumber class]])
	{
		SSLProtocol minProtocol = (SSLProtocol)[(NSNumber *)value intValue];
		if (minProtocol != kSSLProtocolUnknown)
		{
			status = SSLSetProtocolVersionMin(sslContext, minProtocol);
			if (status != noErr)
			{
				[self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMin"]];
				return;
			}
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLProtocolVersionMin. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLProtocolVersionMin."]];
		return;
	}
	
	// 5. GCDAsyncSocketSSLProtocolVersionMax
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLProtocolVersionMax];
	if ([value isKindOfClass:[NSNumber class]])
	{
		SSLProtocol maxProtocol = (SSLProtocol)[(NSNumber *)value intValue];
		if (maxProtocol != kSSLProtocolUnknown)
		{
			status = SSLSetProtocolVersionMax(sslContext, maxProtocol);
			if (status != noErr)
			{
				[self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMax"]];
				return;
			}
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLProtocolVersionMax. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLProtocolVersionMax."]];
		return;
	}
	
	// 6. GCDAsyncSocketSSLSessionOptionFalseStart
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLSessionOptionFalseStart];
	if ([value isKindOfClass:[NSNumber class]])
	{
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionFalseStart, [value boolValue]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionFalseStart)"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLSessionOptionFalseStart. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLSessionOptionFalseStart."]];
		return;
	}
	
	// 7. GCDAsyncSocketSSLSessionOptionSendOneByteRecord
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLSessionOptionSendOneByteRecord];
	if ([value isKindOfClass:[NSNumber class]])
	{
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionSendOneByteRecord, [value boolValue]);
		if (status != noErr)
		{
			[self closeWithError:
			  [self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionSendOneByteRecord)"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLSessionOptionSendOneByteRecord."
		             @" Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLSessionOptionSendOneByteRecord."]];
		return;
	}
	
	// 8. GCDAsyncSocketSSLCipherSuites
	
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLCipherSuites];
	if ([value isKindOfClass:[NSArray class]])
	{
		NSArray *cipherSuites = (NSArray *)value;
		NSUInteger numberCiphers = [cipherSuites count];
		SSLCipherSuite ciphers[numberCiphers];
		
		NSUInteger cipherIndex;
		for (cipherIndex = 0; cipherIndex < numberCiphers; cipherIndex++)
		{
			NSNumber *cipherObject = [cipherSuites objectAtIndex:cipherIndex];
			ciphers[cipherIndex] = [cipherObject shortValue];
		}
		
		status = SSLSetEnabledCiphers(sslContext, ciphers, numberCiphers);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetEnabledCiphers"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLCipherSuites. Value must be of type NSArray.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLCipherSuites."]];
		return;
	}
	
	// 9. GCDAsyncSocketSSLDiffieHellmanParameters
	
	#if !TARGET_OS_IPHONE
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLDiffieHellmanParameters];
	if ([value isKindOfClass:[NSData class]])
	{
		NSData *diffieHellmanData = (NSData *)value;
		
		status = SSLSetDiffieHellmanParams(sslContext, [diffieHellmanData bytes], [diffieHellmanData length]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetDiffieHellmanParams"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLDiffieHellmanParameters. Value must be of type NSData.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLDiffieHellmanParameters."]];
		return;
	}
	#endif
	
	// DEPRECATED checks
	
	// 10. kCFStreamSSLAllowsAnyRoot
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsAnyRoot];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsAnyRoot"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsAnyRoot"]];
		return;
	}
	
	// 11. kCFStreamSSLAllowsExpiredRoots
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredRoots];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"]];
		return;
	}
	
	// 12. kCFStreamSSLValidatesCertificateChain
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLValidatesCertificateChain];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLValidatesCertificateChain"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLValidatesCertificateChain"]];
		return;
	}
	
	// 13. kCFStreamSSLAllowsExpiredCertificates
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredCertificates];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"]];
		return;
	}
	
	// 14. kCFStreamSSLLevel
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLLevel];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLLevel"
		             @" - You must use GCDAsyncSocketSSLProtocolVersionMin & GCDAsyncSocketSSLProtocolVersionMax");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLLevel"]];
		return;
	}
	
	// Setup the sslPreBuffer
	// 
	// Any data in the preBuffer needs to be moved into the sslPreBuffer,
	// as this data is now part of the secure read stream.
	
    //初始化 SSL 提前缓冲 也是4kb
	sslPreBuffer = [[GCDAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
	//获取 preBuffer 可读大小
	size_t preBufferLength  = [preBuffer availableBytes];
	
    //如果有可读内容
	if (preBufferLength > 0)
	{
        //确保 SSL 提前缓冲区的大小
		[sslPreBuffer ensureCapacityForWrite:preBufferLength];
		//从readBuffer开始读，读这个长度到 SSL 提前缓冲的 writeBuffer 中去
		memcpy([sslPreBuffer writeBuffer], [preBuffer readBuffer], preBufferLength);
        //移动提前的读 buffer
		[preBuffer didRead:preBufferLength];
        //移动 sslpreBuffer 的写 buffer
		[sslPreBuffer didWrite:preBufferLength];
	}
	
    //拿到上次错误的 code,并且让上次错误的 code = 没错
	sslErrCode = lastSSLHandshakeError = noErr;
	
	// Start the SSL Handshake process
	//开始 SSL 握手过程
	[self ssl_continueSSLHandshake];
}

//SSL 的握手
- (void)ssl_continueSSLHandshake
{
	LogTrace();
	
	// If the return value is noErr, the session is ready for normal secure communication.
	// If the return value is errSSLWouldBlock, the SSLHandshake function must be called again.
	// If the return value is errSSLServerAuthCompleted, we ask delegate if we should trust the
	// server and then call SSLHandshake again to resume the handshake or close the connection
	// errSSLPeerBadCert SSL error.
	// Otherwise, the return value indicates an error code.
	
    //用我们的 SSL 上下文对象去握手
	OSStatus status = SSLHandshake(sslContext);
    
    //拿到握手的结构，赋值给上次握手的结果
	lastSSLHandshakeError = status;
	
    //如果没错
	if (status == noErr)
	{
		LogVerbose(@"SSLHandshake complete");
		
        //把开始读写 TLS 从标记中移除
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
		
        //把 socket 安全通道标记加上
		flags |=  kSocketSecure;
		
        
        //拿到代理
		__strong id theDelegate = delegate;

		if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				//调用 socket 已经开启安全通道的代理方法
				[theDelegate socketDidSecure:self];
			}});
		}
		
        //停止读写
		[self endCurrentRead];
		[self endCurrentWrite];
		
        //开始下一次读写任务
		[self maybeDequeueRead];
		[self maybeDequeueWrite];
	}
    //如果认证错误
	else if (status == errSSLPeerAuthCompleted)
	{
		LogVerbose(@"SSLHandshake peerAuthCompleted - awaiting delegate approval");
		
		__block SecTrustRef trust = NULL;
        //从 sslContext 拿到证书相关细节
		status = SSLCopyPeerTrust(sslContext, &trust);
		if (status != noErr)
		{
			[self closeWithError:[self sslError:status]];
			return;
		}
		
        //拿到状态值
		int aStateIndex = stateIndex;
		dispatch_queue_t theSocketQueue = socketQueue;
		
		__weak GCDAsyncSocket *weakSelf = self;
		
        //创建一个完整的 block
		void (^comletionHandler)(BOOL) = ^(BOOL shouldTrust){ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			dispatch_async(theSocketQueue, ^{ @autoreleasepool {
				
				if (trust) {
					CFRelease(trust);
					trust = NULL;
				}
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf)
				{
					[strongSelf ssl_shouldTrustPeer:shouldTrust stateIndex:aStateIndex];
				}
			}});
			
		#pragma clang diagnostic pop
		}};
		
		__strong id theDelegate = delegate;
		
		if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReceiveTrust:completionHandler:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
                //调用代理我们自己去 https 认证
				[theDelegate socket:self didReceiveTrust:trust completionHandler:comletionHandler];
			}});
		}
        //没实现代理直接报错关闭连接
		else
		{
			if (trust) {
				CFRelease(trust);
				trust = NULL;
			}
			
			NSString *msg = @"GCDAsyncSocketManuallyEvaluateTrust specified in tlsSettings,"
			                @" but delegate doesn't implement socket:shouldTrustPeer:";
			
			[self closeWithError:[self otherError:msg]];
			return;
		}
	}
    
    //握手错误为 IO阻塞的
	else if (status == errSSLWouldBlock)
	{
		LogVerbose(@"SSLHandshake continues...");
		
		// Handshake continues...
		// 
		// This method will be called again from doReadData or doWriteData.
	}
	else
	{
        //其它错误直接关闭连接
		[self closeWithError:[self sslError:status]];
	}
}

- (void)ssl_shouldTrustPeer:(BOOL)shouldTrust stateIndex:(int)aStateIndex
{
	LogTrace();
	
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring ssl_shouldTrustPeer - invalid state (maybe disconnected)");
		
		// One of the following is true
		// - the socket was disconnected
		// - the startTLS operation timed out
		// - the completionHandler was already invoked once
		
		return;
	}
	
	// Increment stateIndex to ensure completionHandler can only be called once.
	stateIndex++;
	
	if (shouldTrust)
	{
        NSAssert(lastSSLHandshakeError == errSSLPeerAuthCompleted, @"ssl_shouldTrustPeer called when last error is %d and not errSSLPeerAuthCompleted", (int)lastSSLHandshakeError);
		[self ssl_continueSSLHandshake];
	}
	else
	{
		[self closeWithError:[self sslError:errSSLPeerBadCert]];
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

- (void)cf_finishSSLHandshake
{
	LogTrace();
	
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
		
		flags |= kSocketSecure;
		
		__strong id theDelegate = delegate;

		if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socketDidSecure:self];
			}});
		}
		
		[self endCurrentRead];
		[self endCurrentWrite];
		
		[self maybeDequeueRead];
		[self maybeDequeueWrite];
	}
}

- (void)cf_abortSSLHandshake:(NSError *)error
{
	LogTrace();
	
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
		
		[self closeWithError:error];
	}
}

- (void)cf_startTLS
{
	LogTrace();
	
	LogVerbose(@"Starting TLS (via CFStream)...");
	
	if ([preBuffer availableBytes] > 0)
	{
		NSString *msg = @"Invalid TLS transition. Handshake has already been read from socket.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
	[self suspendReadSource];
	[self suspendWriteSource];
	
	socketFDBytesAvailable = 0;
	flags &= ~kSocketCanAcceptBytes;
	flags &= ~kSecureSocketHasBytesAvailable;
	
	flags |=  kUsingCFStreamForTLS;
	
	if (![self createReadAndWriteStream])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamCreatePairWithSocket"]];
		return;
	}
	
	if (![self registerForStreamCallbacksIncludingReadWrite:YES])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
		return;
	}
	
	if (![self addStreamsToRunLoop])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
		return;
	}
	
	NSAssert([currentRead isKindOfClass:[GCDAsyncSpecialPacket class]], @"Invalid read packet for startTLS");
	NSAssert([currentWrite isKindOfClass:[GCDAsyncSpecialPacket class]], @"Invalid write packet for startTLS");
	
	GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
	CFDictionaryRef tlsSettings = (__bridge CFDictionaryRef)tlsPacket->tlsSettings;
	
	// Getting an error concerning kCFStreamPropertySSLSettings ?
	// You need to add the CFNetwork framework to your iOS application.
	
	BOOL r1 = CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, tlsSettings);
	BOOL r2 = CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, tlsSettings);
	
	// For some reason, starting around the time of iOS 4.3,
	// the first call to set the kCFStreamPropertySSLSettings will return true,
	// but the second will return false.
	// 
	// Order doesn't seem to matter.
	// So you could call CFReadStreamSetProperty and then CFWriteStreamSetProperty, or you could reverse the order.
	// Either way, the first call will return true, and the second returns false.
	// 
	// Interestingly, this doesn't seem to affect anything.
	// Which is not altogether unusual, as the documentation seems to suggest that (for many settings)
	// setting it on one side of the stream automatically sets it for the other side of the stream.
	// 
	// Although there isn't anything in the documentation to suggest that the second attempt would fail.
	// 
	// Furthermore, this only seems to affect streams that are negotiating a security upgrade.
	// In other words, the socket gets connected, there is some back-and-forth communication over the unsecure
	// connection, and then a startTLS is issued.
	// So this mostly affects newer protocols (XMPP, IMAP) as opposed to older protocols (HTTPS).
	
	if (!r1 && !r2) // Yes, the && is correct - workaround for apple bug.
	{
		[self closeWithError:[self otherError:@"Error in CFStreamSetProperty"]];
		return;
	}
	
	if (![self openStreams])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamOpen"]];
		return;
	}
	
	LogVerbose(@"Waiting for SSL Handshake to complete...");
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

+ (void)ignore:(id)_
{}

+ (void)startCFStreamThreadIfNeeded
{
	LogTrace();
	
	static dispatch_once_t predicate;
	dispatch_once(&predicate, ^{
		
		cfstreamThreadRetainCount = 0;
		cfstreamThreadSetupQueue = dispatch_queue_create("GCDAsyncSocket-CFStreamThreadSetup", DISPATCH_QUEUE_SERIAL);
	});
	
	dispatch_sync(cfstreamThreadSetupQueue, ^{ @autoreleasepool {
		
		if (++cfstreamThreadRetainCount == 1)
		{
			cfstreamThread = [[NSThread alloc] initWithTarget:self
			                                         selector:@selector(cfstreamThread)
			                                           object:nil];
			[cfstreamThread start];
		}
	}});
}

+ (void)stopCFStreamThreadIfNeeded
{
	LogTrace();
	
	// The creation of the cfstreamThread is relatively expensive.
	// So we'd like to keep it available for recycling.
	// However, there's a tradeoff here, because it shouldn't remain alive forever.
	// So what we're going to do is use a little delay before taking it down.
	// This way it can be reused properly in situations where multiple sockets are continually in flux.
	
	int delayInSeconds = 30;
	dispatch_time_t when = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
	dispatch_after(when, cfstreamThreadSetupQueue, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		if (cfstreamThreadRetainCount == 0)
		{
			LogWarn(@"Logic error concerning cfstreamThread start / stop");
			return_from_block;
		}
		
		if (--cfstreamThreadRetainCount == 0)
		{
			[cfstreamThread cancel]; // set isCancelled flag
			
			// wake up the thread
            [[self class] performSelector:@selector(ignore:)
                                 onThread:cfstreamThread
                               withObject:[NSNull null]
                            waitUntilDone:NO];
            
			cfstreamThread = nil;
		}
		
	#pragma clang diagnostic pop
	}});
}

+ (void)cfstreamThread { @autoreleasepool
{
	[[NSThread currentThread] setName:GCDAsyncSocketThreadName];
	
	LogInfo(@"CFStreamThread: Started");
	
	// We can't run the run loop unless it has an associated input source or a timer.
	// So we'll just create a timer that will never fire - unless the server runs for decades.
	[NSTimer scheduledTimerWithTimeInterval:[[NSDate distantFuture] timeIntervalSinceNow]
	                                 target:self
	                               selector:@selector(ignore:)
	                               userInfo:nil
	                                repeats:YES];
	
	NSThread *currentThread = [NSThread currentThread];
	NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
	
	BOOL isCancelled = [currentThread isCancelled];
	
	while (!isCancelled && [currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
	{
		isCancelled = [currentThread isCancelled];
	}
	
	LogInfo(@"CFStreamThread: Stopped");
}}

//注册 CFStream
+ (void)scheduleCFStreams:(GCDAsyncSocket *)asyncSocket
{
	LogTrace();
    //断言当前线程是 cfstreamThread，不是则报错
	NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
	
    //获取到 runloop
	CFRunLoopRef runLoop = CFRunLoopGetCurrent();
	
    //如果有 readStream
	if (asyncSocket->readStream)
        //注册 readStream 在 runloop 的kCFRunLoopDefaultMode上
		CFReadStreamScheduleWithRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
	//一样
	if (asyncSocket->writeStream)
		CFWriteStreamScheduleWithRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

+ (void)unscheduleCFStreams:(GCDAsyncSocket *)asyncSocket
{
	LogTrace();
	NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
	
	CFRunLoopRef runLoop = CFRunLoopGetCurrent();
	
	if (asyncSocket->readStream)
		CFReadStreamUnscheduleFromRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
	
	if (asyncSocket->writeStream)
		CFWriteStreamUnscheduleFromRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

static void CFReadStreamCallback (CFReadStreamRef stream, CFStreamEventType type, void *pInfo)
{
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)pInfo;
	
	switch(type)
	{
		case kCFStreamEventHasBytesAvailable:
		{
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFReadStreamCallback - HasBytesAvailable");
				
				if (asyncSocket->readStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					// If we set kCFStreamPropertySSLSettings before we opened the streams, this might be a lie.
					// (A callback related to the tcp stream, but not to the SSL layer).
					
					if (CFReadStreamHasBytesAvailable(asyncSocket->readStream))
					{
						asyncSocket->flags |= kSecureSocketHasBytesAvailable;
						[asyncSocket cf_finishSSLHandshake];
					}
				}
				else
				{
					asyncSocket->flags |= kSecureSocketHasBytesAvailable;
					[asyncSocket doReadData];
				}
			}});
			
			break;
		}
		default:
		{
			NSError *error = (__bridge_transfer  NSError *)CFReadStreamCopyError(stream);
			
			if (error == nil && type == kCFStreamEventEndEncountered)
			{
				error = [asyncSocket connectionClosedError];
			}
			
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFReadStreamCallback - Other");
				
				if (asyncSocket->readStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					[asyncSocket cf_abortSSLHandshake:error];
				}
				else
				{
					[asyncSocket closeWithError:error];
				}
			}});
			
			break;
		}
	}
	
}

static void CFWriteStreamCallback (CFWriteStreamRef stream, CFStreamEventType type, void *pInfo)
{
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)pInfo;
	
	switch(type)
	{
		case kCFStreamEventCanAcceptBytes:
		{
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFWriteStreamCallback - CanAcceptBytes");
				
				if (asyncSocket->writeStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					// If we set kCFStreamPropertySSLSettings before we opened the streams, this might be a lie.
					// (A callback related to the tcp stream, but not to the SSL layer).
					
					if (CFWriteStreamCanAcceptBytes(asyncSocket->writeStream))
					{
						asyncSocket->flags |= kSocketCanAcceptBytes;
						[asyncSocket cf_finishSSLHandshake];
					}
				}
				else
				{
					asyncSocket->flags |= kSocketCanAcceptBytes;
					[asyncSocket doWriteData];
				}
			}});
			
			break;
		}
		default:
		{
			NSError *error = (__bridge_transfer NSError *)CFWriteStreamCopyError(stream);
			
			if (error == nil && type == kCFStreamEventEndEncountered)
			{
				error = [asyncSocket connectionClosedError];
			}
			
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFWriteStreamCallback - Other");
				
				if (asyncSocket->writeStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					[asyncSocket cf_abortSSLHandshake:error];
				}
				else
				{
					[asyncSocket closeWithError:error];
				}
			}});
			
			break;
		}
	}
	
}

//创建读写 stream
- (BOOL)createReadAndWriteStream
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	//如果有一个有值 就返回
	if (readStream || writeStream)
	{
		// Streams already created
		return YES;
	}
	//拿到 socket 首先是socket4FD，其次是socket6FD  都没有才是socketUN， socketUN应该是 unix 的 socket 结构体
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	
    //如果都为空 返回 NO
	if (socketFD == SOCKET_NULL)
	{
		// Cannot create streams without a file descriptor
		return NO;
	}
	
    //如果非连接 返回 NO
	if (![self isConnected])
	{
		// Cannot create streams until file descriptor is connected
		return NO;
	}
	
	LogVerbose(@"Creating read and write stream...");
	
    //下面的接口用于创建一对 socket stream 一个用于读取， 一个用于写入
	CFStreamCreatePairWithSocket(NULL, (CFSocketNativeHandle)socketFD, &readStream, &writeStream);
	
	// The kCFStreamPropertyShouldCloseNativeSocket property should be false by default (for our case).
	// But let's not take any chances.
	
    //读写的 stream 都设置成不会随着绑定的 socket 一起 close, release
    //kCFBooleanFalse 不一起 kCFBooleanTrue 一起
	if (readStream)
		CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
	if (writeStream)
		CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
	
    //如果有一个为空
	if ((readStream == NULL) || (writeStream == NULL))
	{
		LogWarn(@"Unable to create read and write stream...");
		//关闭对应的 stream
		if (readStream)
		{
			CFReadStreamClose(readStream);
			CFRelease(readStream);
			readStream = NULL;
		}
		if (writeStream)
		{
			CFWriteStreamClose(writeStream);
			CFRelease(writeStream);
			writeStream = NULL;
		}
		//返回创建失败
		return NO;
	}
	//创建成功
	return YES;
}

//注册 stream 的回调
- (BOOL)registerForStreamCallbacksIncludingReadWrite:(BOOL)includeReadWrite
{
	LogVerbose(@"%@ %@", THIS_METHOD, (includeReadWrite ? @"YES" : @"NO"));
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //判断读写 stream 是不是都为空
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //客户端 stream 上下文对象
	streamContext.version = 0;
	streamContext.info = (__bridge void *)(self);
	streamContext.retain = nil;
	streamContext.release = nil;
	streamContext.copyDescription = nil;
	
    //设置一个 CF 的 flag 两种，  一种是错误发生的时候，一种是 stream 事件结束
	CFOptionFlags readStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
    //如果包含读写
	if (includeReadWrite)
        //仍然有 byte 要读的时候
		readStreamEvents |= kCFStreamEventHasBytesAvailable;
	
    //给读 stream 设置客户端，会在之前设置的那些标记下回调函数 CFReadStreamCallback。 设置失败的话直接返回 NO
	if (!CFReadStreamSetClient(readStream, readStreamEvents, &CFReadStreamCallback, &streamContext))
	{
		return NO;
	}
	
    //写的 flag, 也一样
	CFOptionFlags writeStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
	if (includeReadWrite)
		writeStreamEvents |= kCFStreamEventCanAcceptBytes;
	
	if (!CFWriteStreamSetClient(writeStream, writeStreamEvents, &CFWriteStreamCallback, &streamContext))
	{
		return NO;
	}
	
    //走到最后说明读写都设置回调成功， 返回 YES
	return YES;
}

//把 stream 添加到 runloop 上
- (BOOL)addStreamsToRunLoop
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //判断 flag 里是否包含 kAddedStreamsToRunLoop 没添加过则添加
	if (!(flags & kAddedStreamsToRunLoop))
	{
		LogVerbose(@"Adding streams to runloop...");
		
		[[self class] startCFStreamThreadIfNeeded];
        //在开启的线程中去执行，阻塞试的
        dispatch_sync(cfstreamThreadSetupQueue, ^{
            [[self class] performSelector:@selector(scheduleCFStreams:)
                                 onThread:cfstreamThread
                               withObject:self
                            waitUntilDone:YES];
        });
        //添加标识
		flags |= kAddedStreamsToRunLoop;
	}
	
	return YES;
}

- (void)removeStreamsFromRunLoop
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
	if (flags & kAddedStreamsToRunLoop)
	{
		LogVerbose(@"Removing streams from runloop...");
        
        dispatch_sync(cfstreamThreadSetupQueue, ^{
            [[self class] performSelector:@selector(unscheduleCFStreams:)
                                 onThread:cfstreamThread
                               withObject:self
                            waitUntilDone:YES];
        });
		[[self class] stopCFStreamThreadIfNeeded];
		
		flags &= ~kAddedStreamsToRunLoop;
	}
}

//打开 stream
- (BOOL)openStreams
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //断言读写 stream 都不会为空
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //返回 stream 的状态
	CFStreamStatus readStatus = CFReadStreamGetStatus(readStream);
	CFStreamStatus writeStatus = CFWriteStreamGetStatus(writeStream);
	
    //如果有任意一个没有开启
	if ((readStatus == kCFStreamStatusNotOpen) || (writeStatus == kCFStreamStatusNotOpen))
	{
		LogVerbose(@"Opening read and write stream...");
		//开启
		BOOL r1 = CFReadStreamOpen(readStream);
		BOOL r2 = CFWriteStreamOpen(writeStream);
		
        //有一个开启失败
		if (!r1 || !r2)
		{
			LogError(@"Error in CFStreamOpen");
			return NO;
		}
	}
	
	return YES;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Advanced
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * See header file for big discussion of this method.
**/
- (BOOL)autoDisconnectOnClosedReadStream
{
	// Note: YES means kAllowHalfDuplexConnection is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kAllowHalfDuplexConnection) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kAllowHalfDuplexConnection) == 0);
		});
		
		return result;
	}
}

/**
 * See header file for big discussion of this method.
**/
- (void)setAutoDisconnectOnClosedReadStream:(BOOL)flag
{
	// Note: YES means kAllowHalfDuplexConnection is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kAllowHalfDuplexConnection;
		else
			config |= kAllowHalfDuplexConnection;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}


/**
 * See header file for big discussion of this method.
**/
- (void)markSocketQueueTargetQueue:(dispatch_queue_t)socketNewTargetQueue
{
	void *nonNullUnusedPointer = (__bridge void *)self;
	dispatch_queue_set_specific(socketNewTargetQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
}

/**
 * See header file for big discussion of this method.
**/
- (void)unmarkSocketQueueTargetQueue:(dispatch_queue_t)socketOldTargetQueue
{
	dispatch_queue_set_specific(socketOldTargetQueue, IsOnSocketQueueOrTargetQueueKey, NULL, NULL);
}

/**
 * See header file for big discussion of this method.
**/
- (void)performBlock:(dispatch_block_t)block
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
}

/**
 * Questions? Have you read the header file?
**/
- (int)socketFD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	if (socket4FD != SOCKET_NULL)
		return socket4FD;
	else
		return socket6FD;
}

/**
 * Questions? Have you read the header file?
**/
- (int)socket4FD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	return socket4FD;
}

/**
 * Questions? Have you read the header file?
**/
- (int)socket6FD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	return socket6FD;
}

#if TARGET_OS_IPHONE

/**
 * Questions? Have you read the header file?
**/
- (CFReadStreamRef)readStream
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	if (readStream == NULL)
		[self createReadAndWriteStream];
	
	return readStream;
}

/**
 * Questions? Have you read the header file?
**/
- (CFWriteStreamRef)writeStream
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	if (writeStream == NULL)
		[self createReadAndWriteStream];
	
	return writeStream;
}

- (BOOL)enableBackgroundingOnSocketWithCaveat:(BOOL)caveat
{
	if (![self createReadAndWriteStream])
	{
		// Error occurred creating streams (perhaps socket isn't open)
		return NO;
	}
	
	BOOL r1, r2;
	
	LogVerbose(@"Enabling backgrouding on socket");
	
	r1 = CFReadStreamSetProperty(readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
	r2 = CFWriteStreamSetProperty(writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
	
	if (!r1 || !r2)
	{
		return NO;
	}
	
	if (!caveat)
	{
		if (![self openStreams])
		{
			return NO;
		}
	}
	
	return YES;
}

/**
 * Questions? Have you read the header file?
**/
- (BOOL)enableBackgroundingOnSocket
{
	LogTrace();
	
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NO;
	}
	
	return [self enableBackgroundingOnSocketWithCaveat:NO];
}

- (BOOL)enableBackgroundingOnSocketWithCaveat // Deprecated in iOS 4.???
{
	// This method was created as a workaround for a bug in iOS.
	// Apple has since fixed this bug.
	// I'm not entirely sure which version of iOS they fixed it in...
	
	LogTrace();
	
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NO;
	}
	
	return [self enableBackgroundingOnSocketWithCaveat:YES];
}

#endif

- (SSLContextRef)sslContext
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	return sslContext;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Class Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//根据 host port
+ (NSMutableArray *)lookupHost:(NSString *)host port:(uint16_t)port error:(NSError **)errPtr
{
	LogTrace();
	
	NSMutableArray *addresses = nil;
	NSError *error = nil;
	//如果 Host 是这 localhost 或者 loopback
	if ([host isEqualToString:@"localhost"] || [host isEqualToString:@"loopback"])
	{
		// Use LOOPBACK address
		struct sockaddr_in nativeAddr4;
		nativeAddr4.sin_len         = sizeof(struct sockaddr_in);
		nativeAddr4.sin_family      = AF_INET;
		nativeAddr4.sin_port        = htons(port);
		nativeAddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        
        //占位置0
		memset(&(nativeAddr4.sin_zero), 0, sizeof(nativeAddr4.sin_zero));
		
        //ipv6
		struct sockaddr_in6 nativeAddr6;
		nativeAddr6.sin6_len        = sizeof(struct sockaddr_in6);
		nativeAddr6.sin6_family     = AF_INET6;
		nativeAddr6.sin6_port       = htons(port);
		nativeAddr6.sin6_flowinfo   = 0;
		nativeAddr6.sin6_addr       = in6addr_loopback;
		nativeAddr6.sin6_scope_id   = 0;
		
		// Wrap the native address structures
		
		NSData *address4 = [NSData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
		NSData *address6 = [NSData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
		
        //两个添加进数组
		addresses = [NSMutableArray arrayWithCapacity:2];
		[addresses addObject:address4];
		[addresses addObject:address6];
	}
	else
	{
        //拿到 port String
		NSString *portStr = [NSString stringWithFormat:@"%hu", port];
		
        //定义三个 addrInfo  是一个 sockaddr 结构的链表而不是一个地址清单
		struct addrinfo hints, *res, *res0;
		//初始化为0
		memset(&hints, 0, sizeof(hints));
        
        //返回的是适用于指定主机名和服务名且适合任何协议族的地址
		hints.ai_family   = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		
        //根据 host port 去获取地址信息
		int gai_error = getaddrinfo([host UTF8String], [portStr UTF8String], &hints, &res0);
		
        //出错
		if (gai_error)
		{
            //获取到错误
			error = [self gaiError:gai_error];
		}
        //正确获取到 addrInfo
		else
		{
            
			NSUInteger capacity = 0;
            //遍历 res0
			for (res = res0; res; res = res->ai_next)
			{
                //如果 IPV4 IUPV6的 capacity + 1
				if (res->ai_family == AF_INET || res->ai_family == AF_INET6) {
					capacity++;
				}
			}
			// 生成一个地址数组，数组为 capacity 大小
			addresses = [NSMutableArray arrayWithCapacity:capacity];
			//再去遍历，为什么不一次遍历完，仅仅是为了限制数组的大小
			for (res = res0; res; res = res->ai_next)
			{
                //IPV4
				if (res->ai_family == AF_INET)
				{
					// Found IPv4 address.
					// Wrap the native address structure, and add to results.
					//加到数组中
					NSData *address4 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
					[addresses addObject:address4];
				}
				else if (res->ai_family == AF_INET6)
				{
					// Fixes connection issues with IPv6
					// https://github.com/robbiehanson/CocoaAsyncSocket/issues/429#issuecomment-222477158
					
					// Found IPv6 address.
					// Wrap the native address structure, and add to results.
					//强转
					struct sockaddr_in6 *sockaddr = (struct sockaddr_in6 *)res->ai_addr;
                    //拿到 port
					in_port_t *portPtr = &sockaddr->sin6_port;
                    //如果 port 为0
					if ((portPtr != NULL) && (*portPtr == 0)) {
                        //赋值，用传进来的 port
					        *portPtr = htons(port);
					}
                    //添加到数组
					NSData *address6 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
					[addresses addObject:address6];
				}
			}
            //对应 getaddrinfo 释放内存
			freeaddrinfo(res0);
			//如果地址是一个没有，报错 EAI_FAIL：名字解析中不可恢复的失败
			if ([addresses count] == 0)
			{
				error = [self gaiError:EAI_FAIL];
			}
		}
	}
	//赋值错误
	if (errPtr) *errPtr = error;
    //返回地址
	return addresses;
}

+ (NSString *)hostFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
	char addrBuf[INET_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET, &pSockaddr4->sin_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
	{
		addrBuf[0] = '\0';
	}
	
	return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

+ (NSString *)hostFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
	char addrBuf[INET6_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET6, &pSockaddr6->sin6_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
	{
		addrBuf[0] = '\0';
	}
	
	return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

+ (uint16_t)portFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
	return ntohs(pSockaddr4->sin_port);
}

+ (uint16_t)portFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
	return ntohs(pSockaddr6->sin6_port);
}

+ (NSURL *)urlFromSockaddrUN:(const struct sockaddr_un *)pSockaddr
{
	NSString *path = [NSString stringWithUTF8String:pSockaddr->sun_path];
	return [NSURL fileURLWithPath:path];
}

+ (NSString *)hostFromAddress:(NSData *)address
{
	NSString *host;
	
	if ([self getHost:&host port:NULL fromAddress:address])
		return host;
	else
		return nil;
}

+ (uint16_t)portFromAddress:(NSData *)address
{
	uint16_t port;
	
	if ([self getHost:NULL port:&port fromAddress:address])
		return port;
	else
		return 0;
}

+ (BOOL)isIPv4Address:(NSData *)address
{
	if ([address length] >= sizeof(struct sockaddr))
	{
		const struct sockaddr *sockaddrX = [address bytes];
		
		if (sockaddrX->sa_family == AF_INET) {
			return YES;
		}
	}
	
	return NO;
}

+ (BOOL)isIPv6Address:(NSData *)address
{
	if ([address length] >= sizeof(struct sockaddr))
	{
		const struct sockaddr *sockaddrX = [address bytes];
		
		if (sockaddrX->sa_family == AF_INET6) {
			return YES;
		}
	}
	
	return NO;
}

+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr fromAddress:(NSData *)address
{
	return [self getHost:hostPtr port:portPtr family:NULL fromAddress:address];
}

+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr family:(sa_family_t *)afPtr fromAddress:(NSData *)address
{
	if ([address length] >= sizeof(struct sockaddr))
	{
		const struct sockaddr *sockaddrX = [address bytes];
		
		if (sockaddrX->sa_family == AF_INET)
		{
			if ([address length] >= sizeof(struct sockaddr_in))
			{
				struct sockaddr_in sockaddr4;
				memcpy(&sockaddr4, sockaddrX, sizeof(sockaddr4));
				
				if (hostPtr) *hostPtr = [self hostFromSockaddr4:&sockaddr4];
				if (portPtr) *portPtr = [self portFromSockaddr4:&sockaddr4];
				if (afPtr)   *afPtr   = AF_INET;
				
				return YES;
			}
		}
		else if (sockaddrX->sa_family == AF_INET6)
		{
			if ([address length] >= sizeof(struct sockaddr_in6))
			{
				struct sockaddr_in6 sockaddr6;
				memcpy(&sockaddr6, sockaddrX, sizeof(sockaddr6));
				
				if (hostPtr) *hostPtr = [self hostFromSockaddr6:&sockaddr6];
				if (portPtr) *portPtr = [self portFromSockaddr6:&sockaddr6];
				if (afPtr)   *afPtr   = AF_INET6;
				
				return YES;
			}
		}
	}
	
	return NO;
}

+ (NSData *)CRLFData
{
	return [NSData dataWithBytes:"\x0D\x0A" length:2];
}

+ (NSData *)CRData
{
	return [NSData dataWithBytes:"\x0D" length:1];
}

+ (NSData *)LFData
{
	return [NSData dataWithBytes:"\x0A" length:1];
}

+ (NSData *)ZeroData
{
	return [NSData dataWithBytes:"" length:1];
}

@end	
