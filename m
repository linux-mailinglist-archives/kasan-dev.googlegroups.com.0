Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBL4XXKTAMGQE5ARII2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7084C77111C
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 19:49:37 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe275023d4sf3036557e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691257776; cv=pass;
        d=google.com; s=arc-20160816;
        b=zvwpU0TiWpgUJTOWZxmhmwfcL0rlJlwAdt/T8O9V1c7OOb64PzD5zwQh/sozURZPgI
         VrIn1Ls7H9TiYHde8v7OJEYhpxgiHJng+1w7vVqkDRKpa2Xau5SAghMPvsATbQ9mTnQ8
         o/qQoGZOHR9L47+HjPibt4m3HRPjJYWy9YzFvnb8ct9RnOkTglcDblnl6UIXaJ4oGyZ0
         6KwLuAFH+7oskS4bUbyvPUOeEFS4as0X3fSRyr72pebZsFUZrSV9VTc5Xae8w1ceFy5e
         PKeHnf44mB+1p18gSK0rK0woY06xVQqfRBzGZqzlzfZKei6SC3JMt7FEp3fPLztdtMvF
         nZRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VHDO2qhRFdq7Fpms6tcqrqxaBxWoAK6H+IysOZSaKW0=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=xQJTAcb8IJ9RYUApkIhgJ9LwoPKkBkkdwrUJljWHoSm2b0CiG8Thzg9hhvSS0ZZOU1
         FwbWFJqK6YugfmRspvYDOLf2f9DrVbrTjf2y38l3nddpb5rtFDj5DO+VQBFzRwouFfb1
         Hb+wgFZB02mH37vUFHxImcmiTXE0QesM0tJK/7+2eLaSK5cz2vydU5EqZv9axPjH8FWR
         bfJHoRxAYzksdr6Nb2hcYY0hi7GFsyJNKEfm2L8ef31kxNd+Mg2Rm1JtNRINzxZ4tkh1
         rvyzoBJiwGV6c0iwEhgmHn0KxCGEfTTlN+qS0p2B7IQr3JMEXKUT0aq66kQFruOewBQk
         w1lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jSSlHpr0;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691257776; x=1691862576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VHDO2qhRFdq7Fpms6tcqrqxaBxWoAK6H+IysOZSaKW0=;
        b=bWikWnD4XAHIz9mCQTaM5oUd/XEhepKdCbdisXezUYKB4plG0vItHF5/ljaprOw6I+
         cv+ErhOCo3GEzxUw8mh/S9cwueE7oxa8P67rwOGP1QQ0Bqz1j8CUljfQd/H49C53Urh+
         7qX8OqK/m8+tTfobVUQPcSBxzw+0xTsJ/RTj5DlX2WfJSjk4pzhiVagl087Qre7x3FN7
         m8wwOdV/pGd74YJ3OZY9wVAn6zHF8QFBxGKyuvPnFzMw02B6EqgQnsoIgveMOLYSfxMV
         Aa+xAznGk9tITciy7nj9QjaPl2thzGrN7vJv3nRBD7BlETbdSLa6llJlhP7b2XBRngMn
         OjRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691257776; x=1691862576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VHDO2qhRFdq7Fpms6tcqrqxaBxWoAK6H+IysOZSaKW0=;
        b=FxAiYbcF03MzkLAPFaJTl7hdueVGKYT4eNxI+m7SPrd5NpT4hcdgNmHD12eSsZI3+z
         jFni/fZV77L1vMuVteJ2pdy/vF7XD6HN3aLyIECJbbqxiwn4irAZJxJAluugWbOnO3Od
         f3OLUOwzIhhj27I4gNNvWq1CFY8f3wufIXR8guh+fC6L6+IUU3nvl1kkzmEdu9C9SclK
         ary1CFFTt+/PaMFP/mmezkimJ27ZlwExu6034FAiUNaiRAjnOideMYd6Ap+527WaF/jz
         tsWG3RWTiPF8Cr5PImk8vMl6F3z49MBgge0qj7mt7gIwj6hxrut0aLMVptq07Dx+yCuQ
         3P3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7YcHIgVZIISg0ak+3iyW5cL4ntkC7sxagNIs3ZBKSk+gkQemh
	9fJwew68FSM0U7LDAr2+G+Q=
X-Google-Smtp-Source: AGHT+IFbs+RfPazbAjvuh0nykzd84o/25qbFxQIWP8YGIH1wzOiYmaD38cc25akZixifIWe0utoM5A==
X-Received: by 2002:a05:6512:280c:b0:4fb:744e:17db with SMTP id cf12-20020a056512280c00b004fb744e17dbmr4286187lfb.1.1691257775743;
        Sat, 05 Aug 2023 10:49:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c688:0:b0:522:561f:acdd with SMTP id n8-20020aa7c688000000b00522561facddls329347edq.2.-pod-prod-06-eu;
 Sat, 05 Aug 2023 10:49:34 -0700 (PDT)
X-Received: by 2002:a17:907:760d:b0:998:de72:4c89 with SMTP id jx13-20020a170907760d00b00998de724c89mr4237169ejc.50.1691257774136;
        Sat, 05 Aug 2023 10:49:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691257774; cv=none;
        d=google.com; s=arc-20160816;
        b=QFdhhE2EUOU0KiUAvAM7df9jxkaDeWfM08eL5fgPUABZuEQ8gRy5HuKbcEk6iTSs2z
         h4LjD2ul7Y5pWJ7cyX4Bv6nyT21SziauhvwEoPEXNsuXdeHl/TW56o1i8QPZo2sUKoiW
         raS2xaGtXi36/GJAORswixN8BkGZyiD14buycpeRMyVxWWChc6QwwH05W+CTWwvEqrs8
         qAKSRiWwl1MWn4Zfb2PQUnjJ4w140wqvq2Dk5Wm3HTp8ObVz8AGUUi0ckYv8FW/SOswD
         xKfVb6796NF+HtV6LgowBlsoK9ylO5T3P4r/xnsl/bGFZp9hti4fv5B2Tahi1GsvRpOi
         R1Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=APFaLpzRvkmsd23+nAQve4IWVf1KVk54bqCwJXd8ZvA=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=cZ+UoJjr1FD5DE/YTVWt2qgd3cXvbvI5oddwmyFmUEaGHHZTvbNEDRx/f4wscddUuP
         e+A63wWh7ZONAQuQrK28Pxtm9ESAs40udW9oPL2MSddO5mPZUSbQnKOfn0PmUssLsgU+
         T9WWOxIDGElwnn/7jjatMEVBibo0UddqziOVlLl4/jP0uujbCifXFSiWHzYhqJQazjlO
         WFHaVrHUpLQJN5bOkHOEIb7o69X1KQiRcTcWrD1OhU5ycwtLpqopmOhTmkfj474GanUe
         hrTsTD8hdlxVHHREdpo5gJ7PLRvxws31+8ytnaeG1NZWadX/9kr/R9PkdUMDAqw5QUbW
         SQIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jSSlHpr0;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id vh11-20020a170907d38b00b009885c0ef8d2si410440ejc.1.2023.08.05.10.49.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Aug 2023 10:49:33 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="350638991"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="350638991"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Aug 2023 10:49:31 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="733622471"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="733622471"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga007.fm.intel.com with ESMTP; 05 Aug 2023 10:49:28 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 9F9D5BAB; Sat,  5 Aug 2023 20:50:29 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Petr Mladek <pmladek@suse.com>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Date: Sat,  5 Aug 2023 20:50:26 +0300
Message-Id: <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jSSlHpr0;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

kernel.h is being used as a dump for all kinds of stuff for a long time.
sprintf() and friends are used in many drivers without need of the full
kernel.h dependency train with it.

Here is the attempt on cleaning it up by splitting out sprintf() and
friends.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 include/linux/kernel.h  | 30 +-----------------------------
 include/linux/sprintf.h | 25 +++++++++++++++++++++++++
 lib/test_printf.c       |  1 +
 lib/vsprintf.c          |  1 +
 4 files changed, 28 insertions(+), 29 deletions(-)
 create mode 100644 include/linux/sprintf.h

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index b9e76f717a7e..cee8fe87e9f4 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -29,6 +29,7 @@
 #include <linux/panic.h>
 #include <linux/printk.h>
 #include <linux/build_bug.h>
+#include <linux/sprintf.h>
 #include <linux/static_call_types.h>
 #include <linux/instruction_pointer.h>
 #include <asm/byteorder.h>
@@ -203,35 +204,6 @@ static inline void might_fault(void) { }
 
 void do_exit(long error_code) __noreturn;
 
-extern int num_to_str(char *buf, int size,
-		      unsigned long long num, unsigned int width);
-
-/* lib/printf utilities */
-
-extern __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
-extern __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
-extern __printf(3, 4)
-int snprintf(char *buf, size_t size, const char *fmt, ...);
-extern __printf(3, 0)
-int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
-extern __printf(3, 4)
-int scnprintf(char *buf, size_t size, const char *fmt, ...);
-extern __printf(3, 0)
-int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
-extern __printf(2, 3) __malloc
-char *kasprintf(gfp_t gfp, const char *fmt, ...);
-extern __printf(2, 0) __malloc
-char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
-extern __printf(2, 0)
-const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
-
-extern __scanf(2, 3)
-int sscanf(const char *, const char *, ...);
-extern __scanf(2, 0)
-int vsscanf(const char *, const char *, va_list);
-
-extern int no_hash_pointers_enable(char *str);
-
 extern int get_option(char **str, int *pint);
 extern char *get_options(const char *str, int nints, int *ints);
 extern unsigned long long memparse(const char *ptr, char **retptr);
diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
new file mode 100644
index 000000000000..9ca23bcf9f42
--- /dev/null
+++ b/include/linux/sprintf.h
@@ -0,0 +1,25 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KERNEL_SPRINTF_H_
+#define _LINUX_KERNEL_SPRINTF_H_
+
+#include <linux/compiler_attributes.h>
+#include <linux/types.h>
+
+int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
+
+__printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
+__printf(2, 0) int vsprintf(char *buf, const char *, va_list);
+__printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
+__printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
+__printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
+__printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
+__printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
+
+__scanf(2, 3) int sscanf(const char *, const char *, ...);
+__scanf(2, 0) int vsscanf(const char *, const char *, va_list);
+
+int no_hash_pointers_enable(char *str);
+
+#endif	/* _LINUX_KERNEL_SPRINTF_H */
diff --git a/lib/test_printf.c b/lib/test_printf.c
index 2ab09a0dc841..5adca19d34e2 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -19,6 +19,7 @@
 #include <linux/rtc.h>
 #include <linux/slab.h>
 #include <linux/socket.h>
+#include <linux/sprintf.h>
 #include <linux/string.h>
 
 #include "../tools/testing/selftests/kselftest_module.h"
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index b17e0744a7bc..c89719586d0c 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -35,6 +35,7 @@
 #include <linux/property.h>
 #include <linux/rtc.h>
 #include <linux/siphash.h>
+#include <linux/sprintf.h>
 #include <linux/stdarg.h>
 #include <linux/string.h>
 #include <linux/string_helpers.h>
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805175027.50029-3-andriy.shevchenko%40linux.intel.com.
