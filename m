Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBNXMWKTAMGQE5F4XZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B7D576FBF1
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:26:32 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2b9da035848sf19514641fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:26:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691137592; cv=pass;
        d=google.com; s=arc-20160816;
        b=h8cC6fxMAVreTPU+gDn4HOiDd6rtmJvVHD3z1OzkV/+j0j8J+hvCV+4Iw15Xzve/of
         VHgXAUwXT1ojebE6SKltMfvi9ZGhNp2ApDQGIDbNORzeZffTi2/swHi1uNXNh1UnACx8
         bkrcxRykxVb8Nq/T22VlthgMcD0X4JB2Mi91yne98oGR74fj+KiDdvHpblrx83cbUK+M
         HNeHct109rOOdyhaAuRrkmh/6zTyUrRSaPBoaois6AkBHTgm+hHB4FXt/IL6rkbUISw2
         LZBokzoNtzn7xflFNDsFdFzEGkRQ7VbYhdWjBvOOh8vmRvjsBOUPD19zn0+3FQmltxKt
         f1yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RvFlRTZ5pc8AophDPUqTyKvfifJcsRtSFSizGcRVPkk=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=MD40Jk6CjWjR/lCsT1A4KfrSG0dJMhLvEkGj7dH259TMadEZjyomX2Cg4+O09JXinH
         H6tFmeVP+6i91/atagNZXvlCGV7SEovbnCKUbBVo9Pqdzxe8xsL5jeCRtMQB1Vw+aLXp
         xsPfZjhJQChNSUiPO7tFV0J4LYm6S2M/SMBkyb2KZMt22u0Kw8Tu+mzVI9ylrSNNOXGX
         UsNX1/y9apRPw4noMv3Al+PRfor3jTnjpM9xz83E+QEq2NoA/CdojXbBpJT0r3MEaq+I
         fj4I1idpH/XCjuWd8A/XEkxANjcfs/Da6sH/D2UVP6JVRmsjy5DMfG0PhhCzonxRzyW+
         vY/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ly902YKJ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691137592; x=1691742392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RvFlRTZ5pc8AophDPUqTyKvfifJcsRtSFSizGcRVPkk=;
        b=HwiRTWxF0zWRq2SN1gIj36neRsX7a4Ey4J4W6Gg5SqKkaYURyUYf8A3STye7ZkPdjU
         KVkKNNXIrI7zmLJzMd/gqdPq9Joxu+LH+paZCPPiP6ASjtiOdsRVqvEF+YTwYthH34Ri
         5w/OVZ/plhlHu3kVzu3CFCSGjAiLDfwsZIXbRD89ZgkAGcSoZ7UiAa2XedUbnTfkJIZa
         hGKzVuwH68WIwzZ6xMPnXy4Ct+sPEoNKMGuEb1pC1pzvGGi3Ispmbp3xd5kjzCXcDCm0
         0FR3xYWTg10X+axOSqfaosTlDNyEr73cCVZzNJBt/S7/toaxQzy6GHm1ndgE6kc3r0GE
         b4GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691137592; x=1691742392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RvFlRTZ5pc8AophDPUqTyKvfifJcsRtSFSizGcRVPkk=;
        b=dgAuEPXtpqHUzED+CGnQf+U1UipLkfF1XTPPfLY0H6JuChilbSXD27jHW3t+EDCMl7
         LeuCgfj7RYlj0QOSsHC5gCorak49nx2X3PWWvhJUO1GI/RxsvKx2dq6D35EUKn1pIAGF
         E57vWInjtJWviFCQf87Z/rdsxSThnGWen+TK+n4+dYkZ1EJ6aHniRJmsIACprceB3D86
         IyQYiYDHiFqr5NAdMwQIA5vfQtWVKgIavcABlR/57WJ+aIian5cAIeffKyuzVJA+z8qZ
         HR+CJGrsvk2mc1UbIlajsfDg/Ov8R4hyVjEgGdN1N9Zi9ggVZlrXSFuoPM9QkXOZLCEa
         Uqog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxNFcS5DoPFHF6C3gqe7pEwEPDOS+8fdFHbirlypoQ7bMUziPSC
	/8wq6OE1vqf8jcA9n8/cyrQ=
X-Google-Smtp-Source: AGHT+IFLVa8z1tkVIc3nuclV66moYxusIfe+NnOgmWk0Z0O5EN7zVejCYxsk6QWe4AOjg9cgLohLLw==
X-Received: by 2002:a2e:b78e:0:b0:2b7:ae29:88fd with SMTP id n14-20020a2eb78e000000b002b7ae2988fdmr860450ljo.48.1691137591138;
        Fri, 04 Aug 2023 01:26:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c1:0:b0:2b5:8027:4784 with SMTP id x1-20020a2ea7c1000000b002b580274784ls99375ljp.2.-pod-prod-07-eu;
 Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
X-Received: by 2002:a2e:7a0f:0:b0:2b9:c046:8617 with SMTP id v15-20020a2e7a0f000000b002b9c0468617mr853399ljc.5.1691137589433;
        Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691137589; cv=none;
        d=google.com; s=arc-20160816;
        b=njPxwP4jFEIA4+RQ2DUjxIccIwJMunFgTxvv0ZFpMTzBZsUjWyNo/lk7DZ441UhFo8
         0yqFiPIhbk782ti+bChArXPJZbT2nd/P8aTI7wxKQW2F6aSXmLry0izvoq29TUKXX0kc
         EtfcQspEQfwK0gIQq4xqBFH4XV+du1fT3I9+rzJa7H57iclXGMvQgYU0AhxKacCMDN/C
         ebFl/VY3YDgYLP9cM7sXXv6RY0oIJPG2QNHoHCS4QIS55RhJzOXpOD6qia8XZrvgYAp5
         KQatVS96Iui5FzTNag/PC2EIjKZcHo8yv904R5XzHPuVUUoXfgoSbu7s2reu8wZ7R6Ti
         KNYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xN1TF/cqSYy8egconCIVN+MATNViZmMKhKgDRHlEMBE=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=x64iRy36nVJUodmUXPq/+HwycolTrbDFPi1Kvz+hfcNzP0sYTV3+WkFo6xrtWuOoii
         VZng9VPjZVWiI5CCIcVSa9c0VlHX/A/BJVkwLeVi/jOBNxani4xzfv3SGGGomasWfHNu
         aQ0loc0oF9HEddnok+R/rL2A/mdIUFaij/Gl8xWtbJW9oiGRzbyYGLT6SyOUqQrTmydW
         uHYrud9eHUC/GlZ+EtfvikEoP/KA18saHQECfkYeIIz1UInBmQS8mhBzCwIyGq1qZDbb
         yhvREu+Szo5tKSNiiSjwdRIEdvSYam8Zak7xAhPTd1lH6KZjjIqSJZujH8bjo0dmahSu
         nXqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ly902YKJ;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p27-20020a05600c1d9b00b003fbf22a6ddcsi146408wms.1.2023.08.04.01.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="370090211"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="370090211"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 01:26:24 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="733132237"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="733132237"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga007.fm.intel.com with ESMTP; 04 Aug 2023 01:26:21 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 99899F12; Fri,  4 Aug 2023 11:26:32 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v1 4/4] lib/vsprintf: Split out sprintf() and friends
Date: Fri,  4 Aug 2023 11:26:19 +0300
Message-Id: <20230804082619.61833-5-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ly902YKJ;       spf=none
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
 include/linux/sprintf.h | 24 ++++++++++++++++++++++++
 lib/vsprintf.c          |  1 +
 3 files changed, 26 insertions(+), 29 deletions(-)
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
index 000000000000..00d1fdc70a3e
--- /dev/null
+++ b/include/linux/sprintf.h
@@ -0,0 +1,24 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KERNEL_SPRINTF_H_
+#define _LINUX_KERNEL_SPRINTF_H_
+
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
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index eb0934d02722..e553bc9e18f3 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -34,6 +34,7 @@
 #include <linux/property.h>
 #include <linux/rtc.h>
 #include <linux/siphash.h>
+#include <linux/sprintf.h>
 #include <linux/stdarg.h>
 #include <linux/string_helpers.h>
 #include <linux/time.h>
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804082619.61833-5-andriy.shevchenko%40linux.intel.com.
