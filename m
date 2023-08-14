Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBVVL5GTAMGQEB5LBYNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id BC05F77BDE2
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 18:27:03 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3172a94b274sf2752905f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 09:27:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692030423; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQlvH/vulIWyq2V9Yv7IKp8jTWjx4AQTYDILCd6APkx6AplsmoLHGh7ie6ArdcgWGe
         qGxlfIvxWiLV/f6UoPBwupU55krOfIlQxnw5oKTKYigb+t8/CWza5jvg8cWN2cJQI9z3
         jmoTKs+qwUlKPfg5IXiw9pJovSZxPgcOaj8COSR2E0ChJelFh2nC5rvEQASenvMppc3I
         6TDRDGPTVg5ZZFjKTNBa2kgEwqi3UG5AqBvL7EwjDISzaMAttqhG1eKQIdJr+VbK2q7W
         TrJIsvvMFF3yU/xRy+jxhARMuvv15b6rVGRQQfiaYFgFPjD5z42SrYCZyeQR7f5P+oO/
         3+LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+hkgTL7HEYx26ggYdYPWcijJxOcRT2nKrEruloczJoI=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=CN6VIIK15KDMZS+qrvYKL9sVsOsileEJFYkidq3sG3lgNVE+23V3Htz5+VjdSgYZGW
         U0iIL/IMaJcOaI7OkOllr4yqu3qraM4Iuvh+shox3bjCqlQZVZdX9dpcLPTUjIZkzF+Y
         2x+UGSwoxM0YgukO4gLz9UJ5uWRlUZK9w8HEEjg9p2Pd/hSzsMDkspWhOeQ/MBjRaU5L
         6abdmkzs6jWNhiqNlZGMwwwqGmgzyfWa0rkJWyC4Hc77niZ7OxXuNmvYuIcoMXZ5iOcK
         t11zUyESIvo1G2FQw4brBEW3HZouwSZopSUFoss1YOxtKI5FBjWLpk6LflfeELKcIc1F
         xPBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="gzvX/q6a";
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692030423; x=1692635223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+hkgTL7HEYx26ggYdYPWcijJxOcRT2nKrEruloczJoI=;
        b=sT/uf6VihRJQqrETfx4oDgzXLKQnRhLtTHmGhQlZvc7RL3KqLkqME8NXf6p5aI8O3E
         Dm8e5KKlB1z1NHVDscQiHNOzIbe3pGWvVeKnoMlOXlrWp9VV0s/xL9ln44bZtRbOlXP7
         7ZoOJgf/YCvqMIeSskTB1QPr7k8TXnLWh8lvidHymRfRXue2TfuhqGUOvZa3gwfmYlve
         jC+pBfIF/1plSFfFCOBtd6/kwlm/M9nP1z27eP2t+NI2wl8kCCVPjE60NlIVlRyEUTAD
         Z4qzV04/B6NKRa/OHW1rrymYVZd/ROp4QWhL6fXdWOUNlWV+vFmNM0PLg2Q+4QUH+kRg
         LyVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692030423; x=1692635223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+hkgTL7HEYx26ggYdYPWcijJxOcRT2nKrEruloczJoI=;
        b=GVM5TVhIOtEr3eKCDvurK1g0pudAvoOQQlOVSGN9NB28KrpZHvqCpUobvZeb9YPTBI
         e2AVPfPVE3Vmn90kZ7M4u1rnQzT6k6ihbOFFr+OKErX09J4BXh3eJGeN6rRt8cEWJAiC
         M+EnmmBnaXoXnwgBsPMRIFwc3JO1n5Y49uZLp37ar0ZCLbjZ6mS5NIRBQbOUS9uCS1d4
         UtYlSerI+nAyaIV+bl6GPTX1IBhZ7nx74Y++cpXnpBJMBecoZ1f/M8Rq3Dzvu2PYFHh/
         RKnwxjEcIFQUqRB8ZHyTPD2w4oTglWq7t3JUHsKAEA8yfoPe3PXkdQkPecli7pga6cVA
         Or/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy+tK/Ex+vjXJxDHarqEOFJLmWP39gTV34HnI6TZdC/XIGev2o2
	2JN7717UWF/REyv0hdZUKeY=
X-Google-Smtp-Source: AGHT+IEqkJDVzsb2DOmkVA5YfVuy0O+SqULwt/0wRXlT5fKLSEpXpDg/xDml7tmEyIAQ8qQ5p6AdWA==
X-Received: by 2002:a5d:43ca:0:b0:317:6348:8a9d with SMTP id v10-20020a5d43ca000000b0031763488a9dmr7813389wrr.66.1692030422898;
        Mon, 14 Aug 2023 09:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f889:0:b0:317:bdce:7ddb with SMTP id u9-20020adff889000000b00317bdce7ddbls687652wrp.2.-pod-prod-07-eu;
 Mon, 14 Aug 2023 09:27:01 -0700 (PDT)
X-Received: by 2002:a5d:4573:0:b0:317:5de3:86fb with SMTP id a19-20020a5d4573000000b003175de386fbmr7092672wrc.10.1692030421431;
        Mon, 14 Aug 2023 09:27:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692030421; cv=none;
        d=google.com; s=arc-20160816;
        b=cTIJ8TzoSD/zbMiFO1CbwreMR+jukG/1L9aY0nADH+Rf5njdzXtNnRmqbvYCPMwpY2
         JCQa3bm9heJS6w6YCM8TzxvywmZRbxbGeNVxMW721OejTmTIx1BrV+nDx/jHw8RFDINn
         RWss4njXvzNz+QlrXnUCyBhuBPuBsOVgiIKkHnVJV4bfydDjE2ScMT8Bremjd/eZhk3G
         jc7xuKTIoIxwkxjiikudQS5CaCdOb5HJ5KGsdkXyUndJdDxjTGwhn082YnQTc1eKs6yx
         +v3K+twcyyRF9EcfMOHAMAq77TIcc2V1kx4NjqtqSOex+pbztmSJQXS15uzpBBVG6ht0
         lknw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aoQdUnUxWu79/wu/ynaQz9sqIF+EP8+qxQ7gq7KmF9k=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=tLa4RJVns7S8VD3zQ09Dm4gvhkvuchuNkwSFWAFSYuQJPOs7+UJEIeGF4c15XTHEwp
         0+W/1HqJmMYHmo+G5PIlq9u+ML8HkGevtVZren7qoPu5G2bGdYQ+j8U4tCaWT4eGbR83
         5uXYSrIG2LbGhmtMJW4555R4GwS3UniYLrlgzPpYRVGzBKxQMxgoHCRefrjn0E4v1ThU
         OWkd8IuXLUUHpF57z5q57d/f1F+mO/tuOVJDMkSA78PGomj7/ZJik7By/sB9kJi6OqvL
         IMg/LRzvedg9crZK2zc/4XaDTMv1nz5CBoFEv/J0vdVh/MI9k/M+YPEQ9NvVYIrjAqcW
         sFaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="gzvX/q6a";
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id ay13-20020a5d6f0d000000b003179a34f4c4si254788wrb.6.2023.08.14.09.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 09:27:01 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="438415045"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="438415045"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 09:26:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="736565824"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="736565824"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga007.fm.intel.com with ESMTP; 14 Aug 2023 09:26:19 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 62A54370; Mon, 14 Aug 2023 19:33:48 +0300 (EEST)
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
Subject: [PATCH v3 1/2] lib/vsprintf: Split out sprintf() and friends
Date: Mon, 14 Aug 2023 19:33:43 +0300
Message-Id: <20230814163344.17429-2-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
References: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="gzvX/q6a";       spf=none
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
index 7677ebccf3c3..ce749cfac033 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -12,6 +12,7 @@
 #include <linux/random.h>
 #include <linux/rtc.h>
 #include <linux/slab.h>
+#include <linux/sprintf.h>
 #include <linux/string.h>
 
 #include <linux/bitmap.h>
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 40f560959b16..afb88b24fa74 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -34,6 +34,7 @@
 #include <linux/dcache.h>
 #include <linux/cred.h>
 #include <linux/rtc.h>
+#include <linux/sprintf.h>
 #include <linux/time.h>
 #include <linux/uuid.h>
 #include <linux/of.h>
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230814163344.17429-2-andriy.shevchenko%40linux.intel.com.
