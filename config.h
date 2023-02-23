#if defined(__IOS__)
#if  defined(__arm64__)
#include "config/ios/arm64/config.h"
#elif   defined(__arm__)
#include "config/ios/armv7/config.h"
#elif defined(__x86_64__)
#include "config/ios/x86_64/config.h"
#elif defined(__x86__)
#include "config/ios/i386/config.h"
#else
#error Unsupport ARM architecture
#endif
#endif

#if defined(__ANDROID__)
#if  defined(__arm64__)
#include "config/android/arm64-v8a/config.h"
#elif   defined(__arm32__)
#include "config/android/armeabi-v7a/config.h"
#elif defined(__x86_64__)
#include "config/android/x86_64/config.h"
#elif defined(__x86__)
#include "config/android/x86/config.h"
#else
#error Unsupport ARM architecture
#endif
#endif
