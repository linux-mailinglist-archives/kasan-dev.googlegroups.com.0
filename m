Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMVL5GTAMGQEXT5XURI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4425C77BDDE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 18:26:27 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-3fe657c1e68sf729695e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 09:26:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692030387; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkIjO8KaY/3ZuBdIwel6KozB0nPS5f/YtQbYnl4cYMPDEDhzk28LpuYZwvc6caDlOo
         UwQ3e3yylr5/kJfStCA9rpgYnNziBCmKM0dpjeLvBFdfoU3EfxiBPiMVSTNjOtBzEMwD
         Am2rYlz7Djb6xEjcKYfw0+sxgew1FMB52kT5HWHJ1mncUBb6g0/Tj1AC4du50d+vf0Jd
         KYgpUTTLqihQBULdG9FgIVpDjrffB9xwOeNLkC/VlzL8O3dekEwpJR1yydIVxypxpCmh
         j2kQ6GJpFnUxsUuaBAC7x9PYgvYb6/bQcGw0iqQ2tbQJiZ6i/7VUQYngw7SILWXoWtvv
         QJdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rAQW8qPRcI4z07jizfApQ0ITcxBZzPwYBkqSOsddRNQ=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=rbkRj3cvaWGehWxABs47iNv4GBnTTcwg6UnMdq6WP+fgITck1kvoT3zFdpKA3rC3cS
         4uK714xgd/w2DoIyJ9yYiG+dAkoPvFV5Cye4Jh/Gd5GbsrWbZOTRJ6fkEC5NZaTwhI7Z
         dOSVVE2VBT/b0hnE/lwh1KAJarhSSYpIzSPwwDRuljpqqdGvSVZsCeku/lKjAHf52mTS
         XbQ86rVfWkihPkU359KchsP5vXfLVZi4E2NrrV54I+6fhaTwAImMIo6LbkcNprrJN1ys
         Uqh90ROc/wPKIJRsheOsZZ9b2eTu+vTtA9+Xx4vp/9yJqGsR2RhKix1vDusOHnahV6m/
         fUaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QhFAmBw8;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692030387; x=1692635187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rAQW8qPRcI4z07jizfApQ0ITcxBZzPwYBkqSOsddRNQ=;
        b=WvTg/iqXYutCjU5VTVDplptQVHqE0gebEf0dxAzy1IWK9IyPDdXCGtgpZLbZzNZv68
         7RA+JRQ8YuOZhbJ19ewQ8bLE/fFZ2sXiq8C0No7UMDmoysCF0gsvITA7/MqiYhUpfPDJ
         O0r0QAIbnlK/+zNrjWV/bJbiaxraWVgwvZxsVpaL2gBTSaWmHXoDpLhQX3ziKxnyk57d
         LTRK7IYmvf6eEmM2XxgukVkq/8B3y6wk+zLtdhBA+/F18e6vHRSdDcF9DtkuX2E3zZk4
         i4UU+7jGraO0yMvn9/0w82tT+jReMPEU5f8hF0oSuQPiTIqOEB4aSNHCsuWivuYxJggn
         Oa0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692030387; x=1692635187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rAQW8qPRcI4z07jizfApQ0ITcxBZzPwYBkqSOsddRNQ=;
        b=DjPw5xH4338rWQJZ0Ph1DP8FBTxAcErf7p0AUBD3xm9yXePm7BGRFz/vqEB+rnB78R
         ID6Omc7OTk61GD8hYJ5cL0JGaWiz5y0lcgBKgycWRQKMqL77xyymHsEZ8x5fMWZM7Mas
         n3IGqxvFZNj2KBo+t6rj/ub0auOJB9CwNXCOzY0DzVkOXVXK5ZgFHZ3jCcFFn0xo+2Mc
         loxRIkbYyHI1g3kHQYFpiCXDdkBJXf+9cp72N3QhoGJGIf3WaOPto1KfaLS+WerSD+ru
         5qPL30WbzKV7NWvVvH9086GRkyu+zkUvblCk/4CUByXzSLjRBYIOvGaqcf1nXLjrDSZy
         Hgdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzKU6UZq/THyqhoGcNqdgibHO6kiAzlqirryBdzbqQehob7KnqK
	njww8Pvy8KkFCtL1f4jIVm0=
X-Google-Smtp-Source: AGHT+IEE+p3VNFpdxwyH5UNkhTS5LPsh8MB8ySeeSy781jO0cPE7OWnSf4nkZ3svtUz19vI2fugRIA==
X-Received: by 2002:a05:600c:3ba2:b0:3f7:3e85:36a with SMTP id n34-20020a05600c3ba200b003f73e85036amr280262wms.7.1692030386491;
        Mon, 14 Aug 2023 09:26:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f889:0:b0:317:bdce:7ddb with SMTP id u9-20020adff889000000b00317bdce7ddbls687544wrp.2.-pod-prod-07-eu;
 Mon, 14 Aug 2023 09:26:24 -0700 (PDT)
X-Received: by 2002:adf:f303:0:b0:317:ef76:b778 with SMTP id i3-20020adff303000000b00317ef76b778mr8081276wro.63.1692030384811;
        Mon, 14 Aug 2023 09:26:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692030384; cv=none;
        d=google.com; s=arc-20160816;
        b=XQbmiVjbIm80GCWcPyS9R1tHkR0ZnqPNvlQKQcXpU2XIeRJzN/h1GbEtHA3PNeG1UW
         Y7qcKXpb+7Xjmf2VVYLjY3zhZ4Tb+EKLDI4uUi+0KzNpO+PKqWwIHkHp/i0CC1V3sbe7
         L+nqxQ+35dhAlaCS7KUplsgxY3wk3j1t0NQryxUhm4Ijh0t1aT2WBdM9vhR8Ns17flrU
         bI5DEg7dMfh8eXcR5DaieRqwB3kCynZ6oYD29Bw00Dhhz7ho8y7j77oJDMaUSB0robNN
         89HgtzcWVlNM2L53BXSYSkEzfxhHWxtUNzDHfI0Afbx4l5rMM4bgxbAunL6WIZnCsd7M
         K4gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=V3WuGizvUxC5vuhzZZFDGOR3mhwu63Zix/qU35Czt8E=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=rtFbYi0F55h1+ELmnQeWNfC1aMnmRcrR5VikCOE+cPr0VQBcxy+A+iYrvSTNTZ0FUs
         4IJJuDM0rreb1aSgidoP9OazC3LxhyHa8kaF5huqYVd+l2+fAkcfBqmPHfJv1DPFjbvo
         tigEfXHU9bsK+eQmWTQJ8R26P7T1ifIgUyVgFuNnhO4ekWqRvZ6cWFM76tQV1EtSH6ir
         yEZKhsVTif4Cvb9KO4WRtt9TxExvJJYzW5SgDKzcq9OrUSGPaX58HWLzDgQM4fgVRtxj
         NLQFjgUAbaumutlVh1RpQddLCEJoRQt1Bxl20/fQXzqNg+Qw3HZ/KRCBE5qJ8cMAtO8h
         9DoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QhFAmBw8;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id n7-20020a05600c3b8700b003fc3b03cceasi401487wms.1.2023.08.14.09.26.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 09:26:24 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="374852971"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="374852971"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 09:26:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="762991308"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="762991308"
Received: from black.fi.intel.com ([10.237.72.28])
  by orsmga008.jf.intel.com with ESMTP; 14 Aug 2023 09:26:19 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id D6FF8374; Mon, 14 Aug 2023 19:33:48 +0300 (EEST)
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
Subject: [PATCH v3 2/2] lib/vsprintf: Declare no_hash_pointers in sprintf.h
Date: Mon, 14 Aug 2023 19:33:44 +0300
Message-Id: <20230814163344.17429-3-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
References: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QhFAmBw8;       spf=none
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

Sparse is not happy to see non-static variable without declaration:
lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?

Declare respective variable in the sprintf.h. With this, add a comment
to discourage its use if no real need.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Acked-by: Marco Elver <elver@google.com>
---
 include/linux/sprintf.h | 2 ++
 lib/test_printf.c       | 2 --
 mm/kfence/report.c      | 3 +--
 3 files changed, 3 insertions(+), 4 deletions(-)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 9ca23bcf9f42..33dcbec71925 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -20,6 +20,8 @@ __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list
 __scanf(2, 3) int sscanf(const char *, const char *, ...);
 __scanf(2, 0) int vsscanf(const char *, const char *, va_list);
 
+/* These are for specific cases, do not use without real need */
+extern bool no_hash_pointers;
 int no_hash_pointers_enable(char *str);
 
 #endif	/* _LINUX_KERNEL_SPRINTF_H */
diff --git a/lib/test_printf.c b/lib/test_printf.c
index ce749cfac033..69b6a5e177f2 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -42,8 +42,6 @@ KSTM_MODULE_GLOBALS();
 static char *test_buffer __initdata;
 static char *alloced_buffer __initdata;
 
-extern bool no_hash_pointers;
-
 static int __printf(4, 0) __init
 do_test(int bufsize, const char *expect, int elen,
 	const char *fmt, va_list ap)
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 197430a5be4a..c509aed326ce 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -13,6 +13,7 @@
 #include <linux/printk.h>
 #include <linux/sched/debug.h>
 #include <linux/seq_file.h>
+#include <linux/sprintf.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <trace/events/error_report.h>
@@ -26,8 +27,6 @@
 #define ARCH_FUNC_PREFIX ""
 #endif
 
-extern bool no_hash_pointers;
-
 /* Helper function to either print to a seq_file or to console. */
 __printf(2, 3)
 static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230814163344.17429-3-andriy.shevchenko%40linux.intel.com.
