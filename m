Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMEXXKTAMGQEOYWB2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B77D77111D
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 19:49:38 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-4fe3fb358easf3102835e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 10:49:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691257777; cv=pass;
        d=google.com; s=arc-20160816;
        b=iwGBlTANqrLVRWi7nVakbavEF7oC8Fkeb55UMWgKqN950yH45tMps1PgWN9XUYb5Eu
         hsMIzlPC0DiLFr7UQV7L2U54V3DFb1YCqQhqNwJrcQQ4+7d1G4weDwM7kEyVxw3hPdYu
         /LmAnSNiLJ0oWdl5UI+U+8t5xSfvRZSOLYjQlwGDpqPy8OFEDgLIVQ+aSMUbgf1hKjRO
         VCVQi7Lj2NdCF3njdzMFw2fAN6yj9eqy8qAVgv5CqSkx49qS8ctSwvO7uoUL1DLMbYwZ
         KMcFoQ7vu7hEW6T83+O1EWbKaZ/yfn4EkAGvIi0goY+QIwAHg1Lzp+MqdWU1MtoJcaZL
         CmqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tmAGlbs6xa9L94MUCUktu/fldMALxksTSYpcYRMjImQ=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=O88tFL4gICozA9TZdDHnVGheaqzk00qFPJBwDpfmO7BZU+Xxbqyy7Fz7qAyZpQTRxW
         dDhMt/u+IKqsBlKv5f1OyHx2SspEd2vMW52u9mrWXZwWw5towCRMo+X1jst6J4xfqbOe
         homQK5+jU94FEcwERebz3sA+h20maTHyl//w7OEPSHCGo2f5PO/FFfF/mBK9JfAuD0Uj
         1zAVzc6CILql1h5vzhEnRFOimGwXsZjpNDv27J/xKZ7kjHbr9R3DAJx5Yd8ZQwkSpc0p
         ZiOq4B+GNvxMNiVLaojsU1DsMFvVzLH76COCPu5IEKE9M0BaCgjSsJRaSgoN9L27Fb5J
         Ud5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QEC83J08;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691257777; x=1691862577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tmAGlbs6xa9L94MUCUktu/fldMALxksTSYpcYRMjImQ=;
        b=Fuge8Hh2HiWOdsaAsyOTY9m5CCTUURQz2A6mLI4nQmicSWXlTbdvhiugPO2FWMl9qw
         3hXlHtlhJkBLLLZUFZYOig1zrVPp0y+7FXIPBMyRN9t+znHmVsfLIeZ5EKZMjn0BGEdM
         perdTOh625uzYzf3QFvclPaXjBClCy9jdtml4VlP36JuK2chQ8zZdeTFbCL28stC0kLm
         dvuMwb8DzbV8eIsNybetvo0Qp9jqBT+x+lD9yWruV2PjHzNRqR2smvR1/YaH85zOfWLl
         PIllNCIYTAJyYA2gOoK1tLXCrGcJul2LjUIObSRrMNh4OEtkrIVn7saaBPemmKPEgH6Y
         XK9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691257777; x=1691862577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tmAGlbs6xa9L94MUCUktu/fldMALxksTSYpcYRMjImQ=;
        b=k36c7RdVkPIpo80we/+sdOFbA2t4KimHHSrDENpVZhU1SltuoTZg7Qs/rAZ8TcHjSe
         k7wvSGUQ4ul6roVjQvVefmnjlJrfXvXYClIhRxNkc4UAd5aF20HrFm+meM8DsDHgzHs3
         EhZIXfRgWcbL/+RfUh1Yj92GkqPvQqVqcSLwuGKhz506xwXCGH22yyeCo3UVy8bryiB0
         WX0d80XLdVLbldbTMJ+PooKrCl3LaGUmhjoxs/ty+fF1B/DdZNSRHCsvcG1Q7rBXzf3m
         KElg6cuBymhuBBZ8ogCdFbk5pZ70EP14h5/IswxL+rHUTFjI98yepA5K/TWhqWpkLgnT
         Mm3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzJA+w9RIqv45tWAeOLPfhi0Z2A/3SQKfbjDbVdVLEZcw3tFZzD
	IXFc2x91xr0O1gd+JTxLSh0=
X-Google-Smtp-Source: AGHT+IHypqjjXK9OtWW0a9oo+mEem4PMo6phMz8m0Aea0jexJ5vNowKc0m9jvGCasp6HqPyGGLEPwg==
X-Received: by 2002:a05:6512:406:b0:4fe:d0f:b4f7 with SMTP id u6-20020a056512040600b004fe0d0fb4f7mr3355989lfk.65.1691257777075;
        Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:464e:0:b0:4fe:56c5:2906 with SMTP id s14-20020ac2464e000000b004fe56c52906ls220766lfo.0.-pod-prod-07-eu;
 Sat, 05 Aug 2023 10:49:35 -0700 (PDT)
X-Received: by 2002:a05:6512:406:b0:4fe:d0f:b4f7 with SMTP id u6-20020a056512040600b004fe0d0fb4f7mr3355958lfk.65.1691257775118;
        Sat, 05 Aug 2023 10:49:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691257775; cv=none;
        d=google.com; s=arc-20160816;
        b=Is6INToRnulHCgs62Uqxe6HVyCUZ3dnEpRD2z5uEp3FGb68eUU+Xb2HSSlga52p9uO
         WQOkfwT533WBTdMEw2Tw4Z3rGv0vOo42AaOcWPzK5P4o6rh/kbPhZGiH3DnS2ofqjYB7
         kQGU9mzmev6mXsemqmL8PnA16jyBHfrDHzyuK5IIF8/hXTQWgqA8STZvCzO6+taXj/bQ
         0nWOkImQPnUi6MTRkCl+wxlQ163oYIiuXTt6K0ZenB5nTYlkSTkocqZtEoMFr0mGpF+f
         Zq2O/qsbyU8YzNkt9jSdQ7MpxmSBBjkvY97tvPsTL9jZvx5QKbJYRIvUdCsQH/pLvX6F
         S/Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Nl4rJPbf9lJRqy1FTNc3L1ii3wsmDMe6b6YFfzVSNO8=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=bIej9EPrT5F3dFRqujIEwWLwK/tamtAe5+IREMXGCFc7vHHiL/h2m+9BJu8qqsDrq5
         u5MUD/Qc87aao1k3GIrPdO9lZOaZr0dvZ1SeTXA+bd90DOieT/XUYe49LbmW8/b8IZpW
         hkre/aWQLiMsS00ymjk+K5ZEbZKUjWy3qix0u971vlOk86jm8wxU0gQPBmQRunWENmfB
         y2P5XqvG1QekP7PqEnIKQat5xff0WjQi/rNhRSPhKBOyCesH/F610apA5zwGG+/L2KgU
         zohDLVsdecQ6iHhL6K15MxPO1Uq7UTr51UuqxkjOks1d1rILP6GL6AsOjFHsucrb0dA/
         isvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QEC83J08;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id a7-20020ac25e67000000b004fba12b2dfasi289524lfr.2.2023.08.05.10.49.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Aug 2023 10:49:34 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="401292529"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="401292529"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Aug 2023 10:49:32 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="820494257"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="820494257"
Received: from black.fi.intel.com ([10.237.72.28])
  by FMSMGA003.fm.intel.com with ESMTP; 05 Aug 2023 10:49:29 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 905ABF7; Sat,  5 Aug 2023 20:50:29 +0300 (EEST)
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
Subject: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Date: Sat,  5 Aug 2023 20:50:25 +0300
Message-Id: <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QEC83J08;       spf=none
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

Sorting headers alphabetically helps locating duplicates, and
make it easier to figure out where to insert new headers.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 lib/test_printf.c | 17 +++++++----------
 lib/vsprintf.c    | 38 ++++++++++++++++++++------------------
 2 files changed, 27 insertions(+), 28 deletions(-)

diff --git a/lib/test_printf.c b/lib/test_printf.c
index 7677ebccf3c3..2ab09a0dc841 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -5,24 +5,21 @@
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/bitmap.h>
+#include <linux/dcache.h>
+#include <linux/gfp.h>
+#include <linux/in.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
+#include <linux/mm.h>
 #include <linux/module.h>
 #include <linux/printk.h>
+#include <linux/property.h>
 #include <linux/random.h>
 #include <linux/rtc.h>
 #include <linux/slab.h>
-#include <linux/string.h>
-
-#include <linux/bitmap.h>
-#include <linux/dcache.h>
 #include <linux/socket.h>
-#include <linux/in.h>
-
-#include <linux/gfp.h>
-#include <linux/mm.h>
-
-#include <linux/property.h>
+#include <linux/string.h>
 
 #include "../tools/testing/selftests/kselftest_module.h"
 
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 40f560959b16..b17e0744a7bc 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -17,42 +17,44 @@
  * - scnprintf and vscnprintf
  */
 
-#include <linux/stdarg.h>
 #include <linux/build_bug.h>
 #include <linux/clk.h>
 #include <linux/clk-provider.h>
-#include <linux/errname.h>
-#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
-#include <linux/types.h>
-#include <linux/string.h>
+#include <linux/compiler.h>
+#include <linux/cred.h>
 #include <linux/ctype.h>
-#include <linux/kernel.h>
+#include <linux/dcache.h>
+#include <linux/errname.h>
+#include <linux/ioport.h>
 #include <linux/kallsyms.h>
+#include <linux/kernel.h>
 #include <linux/math64.h>
-#include <linux/uaccess.h>
-#include <linux/ioport.h>
-#include <linux/dcache.h>
-#include <linux/cred.h>
+#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
+#include <linux/notifier.h>
+#include <linux/of.h>
+#include <linux/property.h>
 #include <linux/rtc.h>
+#include <linux/siphash.h>
+#include <linux/stdarg.h>
+#include <linux/string.h>
+#include <linux/string_helpers.h>
 #include <linux/time.h>
+#include <linux/types.h>
+#include <linux/uaccess.h>
 #include <linux/uuid.h>
-#include <linux/of.h>
-#include <net/addrconf.h>
-#include <linux/siphash.h>
-#include <linux/compiler.h>
-#include <linux/property.h>
-#include <linux/notifier.h>
+
 #ifdef CONFIG_BLOCK
 #include <linux/blkdev.h>
 #endif
 
+#include <net/addrconf.h>
+
 #include "../mm/internal.h"	/* For the trace_print_flags arrays */
 
-#include <asm/page.h>		/* for PAGE_SIZE */
 #include <asm/byteorder.h>	/* cpu_to_le16 */
+#include <asm/page.h>		/* for PAGE_SIZE */
 #include <asm/unaligned.h>
 
-#include <linux/string_helpers.h>
 #include "kstrtox.h"
 
 /* Disable pointer hashing if requested */
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805175027.50029-2-andriy.shevchenko%40linux.intel.com.
