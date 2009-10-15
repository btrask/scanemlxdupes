/* Copyright (c) 2009, Ben Trask
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * The names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY BEN TRASK ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL BEN TRASK BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */
#import <Foundation/Foundation.h>
#import <openssl/sha.h>

#ifndef NSINTEGER_DEFINED
typedef int NSInteger;
typedef unsigned NSUInteger;
#endif

NSArray *SEDAllSubpaths(NSArray *paths);
NSDictionary *SEDDuplicatesByHashAtPaths(NSArray *paths, BOOL skipHeaders, NSUInteger *outTotalDupes);

int main(int argc, const char *argv[])
{
	NSAutoreleasePool *const pool = [[NSAutoreleasePool alloc] init];
	BOOL showAll = NO, showFullPaths = NO, timeTrial = NO, separateWithSpaces = NO, skipHeaders = NO;
	NSMutableArray *const searchPaths = [NSMutableArray array];
	int i = 1;
	for(; i < argc; i++) if('-' == argv[i][0]) {
		if(strchr(argv[i], 'a')) showAll = YES;
		if(strchr(argv[i], 'p')) showFullPaths = YES;
		if(strchr(argv[i], 't')) timeTrial = YES;
		if(strchr(argv[i], 's')) separateWithSpaces = YES;
		if(strchr(argv[i], 'h')) skipHeaders = YES;
	} else {
		NSString *const argument = [NSString stringWithUTF8String:argv[i]];
		if(![searchPaths containsObject:argument]) [searchPaths addObject:argument];
	}
	if(![searchPaths count]) {
		printf("scanemlxdupes v1. Copyright (c) 2009, Ben Trask. BSD licensed.\n");
		printf("Usage:\n");
		printf("scanemlxdupes [-options] [paths]\n");
		printf("Duplicate emails appear on the same line of output, separated by pipe characters (|).\n");
		printf("Options:\n");
		printf("\t-a\tPrint all, not just duplicates\n");
		printf("\t-p\tPrint full path instead of EMLX number\n");
		printf("\t-t\tPrint time and statistics\n");
		printf("\t-s\tSeparate duplicates with spaces instead of pipes\n");
		printf("\t-h\tSkip message headers when comparing\n");
		[pool drain];
		return 0;
	}
	NSTimeInterval const startTime = timeTrial ? [NSDate timeIntervalSinceReferenceDate] : 0.0f;
	NSArray *const paths = SEDAllSubpaths(searchPaths);
	NSUInteger totalDupeCount;
	NSDictionary *const dupesByHash = SEDDuplicatesByHashAtPaths(paths, skipHeaders, &totalDupeCount);
	if(timeTrial) printf("Scanned %u files in %.1f seconds (%u matches)\n", [paths count], [NSDate timeIntervalSinceReferenceDate] - startTime, totalDupeCount);
	NSArray *dupes;
	NSEnumerator *const dupesEnum = [dupesByHash objectEnumerator];
	while((dupes = [dupesEnum nextObject])) {
		if(!showAll && [dupes count] <= 1) continue;
		NSString *path;
		NSEnumerator *const pathEnum = [dupes objectEnumerator];
		BOOL first = YES;
		while((path = [pathEnum nextObject])) {
			char *format = NULL;
			if(first) format = "%s";
			else if(separateWithSpaces) format = " %s";
			else format = "|%s";
			printf(format, [(showFullPaths ? path : [[path lastPathComponent] stringByDeletingPathExtension]) UTF8String]);
			first = NO;
		}
		printf("\n");
	}
	[pool drain];
	return 0;
}
NSArray *SEDAllSubpaths(NSArray *paths)
{
	NSMutableArray *const subpaths = [NSMutableArray array];
	NSString *path;
	NSEnumerator *const pathEnum = [paths objectEnumerator];
	while((path = [pathEnum nextObject])) {
		NSString *subpathComponent;
		NSDirectoryEnumerator *const subpathComponentEnum = [[NSFileManager defaultManager] enumeratorAtPath:path];
		while((subpathComponent = [subpathComponentEnum nextObject])) {
			NSString *const subpath = [path stringByAppendingPathComponent:subpathComponent];
			if(![subpaths containsObject:subpath]) [subpaths addObject:subpath];
		}
	}
	return subpaths;
}
NSDictionary *SEDDuplicatesByHashAtPaths(NSArray *paths, BOOL skipHeaders, NSUInteger *outTotalDupes)
{
	NSUInteger totalDupes = 0;
	NSMutableDictionary *const duplicatesByHash = [NSMutableDictionary dictionary];
	NSString *path;
	NSEnumerator *const pathEnum = [paths objectEnumerator];
	while((path = [pathEnum nextObject])) {
		NSAutoreleasePool *const pool = [[NSAutoreleasePool alloc] init];
		do {
			if(![@"emlx" isEqualToString:[path pathExtension]]) continue;
			NSData *const fullData = [NSData dataWithContentsOfMappedFile:path];
			if(!fullData) continue;
			UInt8 const *const bytes = (UInt8 const *)[fullData bytes];
			NSUInteger const length = [fullData length];

			NSUInteger marker = 0;
			for(; marker < length; marker++) if(bytes[marker] == '\n') break;
			if(marker >= length) continue;
			NSInteger contentLength = [[[[NSString alloc] initWithData:[fullData subdataWithRange:NSMakeRange(0, marker)] encoding:NSUTF8StringEncoding] autorelease] intValue];
			if(contentLength < 0) continue;
			++marker; // Read past the marker.

			if(skipHeaders) { // Use a simplified Boyer-Moore to find the end of the header (\n\n).
				NSUInteger headerLength = marker;
				for(; headerLength < length - 1; headerLength++) if(bytes[headerLength + 1] != '\n') headerLength++;
				else if(bytes[headerLength] == '\n') break;
				headerLength += 2; // Read past the line breaks.
				if(headerLength >= length - 1 || headerLength >= marker + contentLength) continue;
				contentLength -= headerLength - marker;
				marker = headerLength;
			}

			NSMutableData *const hash = [NSMutableData dataWithLength:SHA_DIGEST_LENGTH];
			SHA(bytes + marker, MIN(length - marker, contentLength), [hash mutableBytes]);

			NSMutableArray *const hashPaths = [duplicatesByHash objectForKey:hash];
			if(hashPaths) {
				[hashPaths addObject:path];
				totalDupes++;
			} else [duplicatesByHash setObject:[NSMutableArray arrayWithObject:path] forKey:hash];
		} while(NO);
		[pool drain];
	}
	if(outTotalDupes) *outTotalDupes = totalDupes;
	return duplicatesByHash;
}
