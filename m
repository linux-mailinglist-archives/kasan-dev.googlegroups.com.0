Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMMXXKTAMGQEQT2GEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 04B4777111E
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 19:49:39 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2b9fa64db5csf34890261fa.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 10:49:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691257778; cv=pass;
        d=google.com; s=arc-20160816;
        b=LqOmDJoCju6483Lv2xwnzm/Oym9k98hcBBBS4E0voWucB1NUUtlv6ehO5FcUryVc+b
         w/xcRwAFt/iNN7EwwmbDQinV36BKm7meYFXyHb63oYtbwL9zDtZ3GmhdXx+l8EvepfPd
         +ZHlDP7VEPuLLFTISu9JUzG01r2ShmMpk7rL/i27hn9s8hvpEBkoiZ6UHXJ/hs4v4KVd
         YngtXQQkaxM0t3R+j16GEMjkY0wRwRO63e2A7Hezp3Nmd2HsJCglQVDKRbmQIOv7e/4l
         aP5VvGzFpkVBlOHbKCumHiy33QQHuRRedNvBRrBv0vi5EJebElQPaqPKRE7ix8FAVMZ0
         BcnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kWDsauM8xtXxsz24vInKy+86CWojlL0A/paeDisgFEU=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=MFIInNdcdloGSPxnVNDoKDnvtSBNWXpnT2tysS25jWRWdv1p/CRzJ7Yrw86mGrtEUm
         voXr3sjek0daX2+wG+32XP1M/VOLsHXT9appGdS7R0ZAzH5XWXRMr2XQNR5/qkG2HJ0V
         pCUe14ZyoUwumilGgpbGYvdaMnqzuyUiSoQWf1Zmg/iug4YajSWXeUqb/owh3iKHjDTz
         FtS/25pcSxcFlNfr8MEvZKxWD0UClYfMIJLMlbxaJoDqhVz8MAGD+DP2jQV0B4tQhs5o
         yHo2HRBFbUvpIkjKnYbOdidlMuB1PVzD9PqPX09LJnRjxY4MzTpNI+DSxCRy9TIBpy+V
         ZWjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NstdhSiN;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691257778; x=1691862578;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kWDsauM8xtXxsz24vInKy+86CWojlL0A/paeDisgFEU=;
        b=WVxsPQsob+cgqjNQ4+VPrsTUy40AG7+dCXdFExGBA2jK71cPYvJCSE33umJc5zMCeh
         m8EXsLoAcDgpORbwLQbhGkE2oq853yfoYwFzJiHAGR5wmfhsC5MnoISKpIofp9EIWqx1
         yWaOfTgZSTpa4WsI0jXEvKJxHJ4jPlol+V3rggtvXfUQSZzPxOlvVU04sYfu62t8u7Fl
         B9DLn4kTYRTcaYN19jqX2PkhH9oDFnXw2UsgD4rVhzv9o3KyCLPwEsLnrUdeZ1919V6D
         25/MK6blS44b/7XRhPa9m+hBLbnoV8vdk3gK5RLpYI+1x+F+m9TXyGoMQyRIwUbFEDsJ
         m9tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691257778; x=1691862578;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kWDsauM8xtXxsz24vInKy+86CWojlL0A/paeDisgFEU=;
        b=TKTs10CqSE/ys+HswnGCf1FtyXTIsO1jsglhqdcNPZzwr4NrcvwOdVt6fgVFb+Ptyf
         VvuQGytfjB47SfXEeuu0Kmz0xs/3LUOWTpQrAJ9VS4lXuAGUobVJnwxv8BQKQFtez+eB
         i1YD2nHkT2TwuEo9wKaHgep3kV051gBqpCavIHPPlJ3m5/gLB8IhRdchDRKeZGmxJdtb
         go/PEOVu5CyD7Om6wWTJfIGhQg/gwqda0n3Q60PCKliMPDZnjRoedKAZ/uLOb0MrCmQf
         t5Qtx3SpnlgioUr1IwHNfzeyiDonJj4NgXvyfCHm1sS7yFcCAJ88ASpuY8+itbzOtwtU
         siig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz/q5vv3x5vlf10zwAMgKqrIcoa5z36O/mOzHCPa8IUMkmqqdyy
	tulq2rE2CbLzrc72yLnNrIY=
X-Google-Smtp-Source: AGHT+IEp8y1cBbhtsDTJxIipagQhVz8URGG05v0f4tU2QjS+ibkVLTFo1OcowdF2f+JkXNob0X4NJQ==
X-Received: by 2002:a05:651c:104f:b0:2b6:9bd3:840e with SMTP id x15-20020a05651c104f00b002b69bd3840emr3572473ljm.21.1691257777734;
        Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a22:b0:2b9:34cb:5cdf with SMTP id
 by34-20020a05651c1a2200b002b934cb5cdfls97668ljb.2.-pod-prod-09-eu; Sat, 05
 Aug 2023 10:49:36 -0700 (PDT)
X-Received: by 2002:ac2:5928:0:b0:4fb:829b:196e with SMTP id v8-20020ac25928000000b004fb829b196emr3036898lfi.2.1691257776087;
        Sat, 05 Aug 2023 10:49:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691257776; cv=none;
        d=google.com; s=arc-20160816;
        b=arDeQW9yJQiXdouJt6Cs8rIATbULP3pWWjQ82/yq8Vy/wOKoWHFqvp7/n9FpoRDSEj
         7EOBESmHrJUwlb790ZTfbflwz2nahGOZPLWUiqwWg4zDMk1/3PhPldBEv07D8ATMZfUt
         Ec5I9EIme8ei2tdwLeKqKbCns5kqm9DGozlCbAc/QWTOqMgT2fSqJXq+XbH0MXPzn97B
         RH7hzHTyL3w+ljGny0tCRccrP2/nVpkYnHrwHGQgWNGROv3u0VMoNnu6y0NRsOavXrIZ
         CYeNalcRcddq6QULt65KwSEkMTMP3wbXt4u6UxaRqToMxsLPdi4m5OhjLcbhplGJixCe
         MOig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YiDRN4KLkDxtCAumuHw+kaAhuG4xOP0mLOcBIaK9ECQ=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=gDWkkH8wf6+MriVmNIy8dlvs/wSjEohkB+yc0yyA3jLpfXMizo/tFXCsnCxh+o4VX5
         9HWN6r4xByka6oBRUTWxV9J+r+r8RG5+6gr+dwL98x/AIHRfTooRWz6/wswCQwvRPEVN
         x+l9JVI0jy11PKFn92YDLIJ7e5kfHb5Y9xv+yiq/UTLb0FL9H7/97CrJ/vVdM94GB/PH
         MFFPUInlMz3nKhHe0ZJZ2IRfIdsaXSvAJapk4WMUHyKDvY9g3dabK9WKr/Vo8qUaNhmo
         ELtUGaJDfxQWAz9HOV113hY4KInlMivT2N8EN9jV6jFVzOLcIeOHITpvdXSN2uQpqwE8
         xALg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NstdhSiN;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id a7-20020ac25e67000000b004fba12b2dfasi289524lfr.2.2023.08.05.10.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Aug 2023 10:49:36 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="401292538"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="401292538"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Aug 2023 10:49:32 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="820494258"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="820494258"
Received: from black.fi.intel.com ([10.237.72.28])
  by FMSMGA003.fm.intel.com with ESMTP; 05 Aug 2023 10:49:29 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id AA2F4F12; Sat,  5 Aug 2023 20:50:29 +0300 (EEST)
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
Subject: [PATCH v2 3/3] lib/vsprintf: Declare no_hash_pointers in sprintf.h
Date: Sat,  5 Aug 2023 20:50:27 +0300
Message-Id: <20230805175027.50029-4-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NstdhSiN;       spf=none
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
index 5adca19d34e2..cf861dc22169 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -39,8 +39,6 @@ KSTM_MODULE_GLOBALS();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805175027.50029-4-andriy.shevchenko%40linux.intel.com.
