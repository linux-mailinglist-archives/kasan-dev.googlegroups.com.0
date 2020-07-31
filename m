Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFHR74QKGQEJSB3YOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E58D02340FF
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:49 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id x20sf13417408plm.15
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183468; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWWJXk/wPkNh8mztGfhKAEfsOTIE0aYuodKwPqoudtAn7sLklaw2MD2Ed1XbO37N/z
         ylWHUpEluE/xPsGCO3yx5TgIJDhTYnP0oBv2YoEoBqUS10l9j8srXfGpxsOn4Vh5yiVZ
         qWpoT6gpgqZ7VguTMN0cNgqIKwwIOnh66QBEym73ZtOZJwqHGcjErOzIhqLBggCXCoNU
         Yiii//b+8KVNLgzA4GlXOX6D+tZa/C6ghcmROxGjxS0TXaFjE3/DThC3WXJnOZPuGMww
         4xCgOsT8EaVCABEHs34mMcQxBvCfc+rvXxFxE/mQX8STQnO+tvGedGhC9SKiSu1IaVlm
         JTMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=pdUL/8llwPGOeBmJ9VPe0glwRNmzTXJIujSPTLZjZck=;
        b=bmByIomXxbn6eg8fTzMpDBDz7q0Kf+kVHkgMtkwpaLVqIP841QGbOrs6U/v093KL4z
         j/mp8/Q62Yu6HK07q9lHvrzq+ckiOdiovydI6BUDfF6l0BQHtbQ5DIh9vcOVZuICZg6M
         uqMKgFTi5EbmkgdM+VBaHTp7lmlE0C4jW/3ZNJObOk2COP4v0sbxyfnRimpF8FXB0HaG
         vIYnzLCrXaRYYO9TWzLA+d0tAbwYwPyaDURaUPvXMJOQYCHJed6VEtYmSCp49tYVPAdF
         zTwICAvauoJNLog3Tj/V+TYDDtEmk4fKqCKY/2AasNPiFgFDp5eV95izHfQboxP9PUu5
         DaIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SQCAbfAY;
       spf=pass (google.com: domain of 3qtmjxwukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qtMjXwUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pdUL/8llwPGOeBmJ9VPe0glwRNmzTXJIujSPTLZjZck=;
        b=TxXdNRd2bhMToKBQwn7EkxABXRMRDrB8aStsqNAVkI2j7lHlr8yBIOWWLaYWAbcSL6
         Sn30ocIX7rLHkwOMBQOaDTKFCICfolxHx4uxoV25pLR6f9SbzOG5x6BCqeEFSE/zdI7f
         XSaFHgdNZmqqngQwq4q+1Tjig6k87Rj52xq6Fqiv0JbxVDzFceOSuQsEQkaOzduJTSAv
         V2w+jFqb2fHeMfqiLEsWphRgzQuhEZJCqA0Nw7xhMQ0DzisipOTMZLNHqefGJJS6u2lZ
         Xmd5D6GDGrozQ9q4TfezB4t21YFrTTPZ3zEg7LYsebheBybhJ+Sns+EFF0M7EpAH2/g3
         c7hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pdUL/8llwPGOeBmJ9VPe0glwRNmzTXJIujSPTLZjZck=;
        b=g8KbN9T4VjP7vHy9BedFaT8DClSWpRA3nNLgGQl3Lp+j0jyQuK7BTgtdCiKXO/B01B
         xmulkYVGEID2xynL/rqm/U05Hs2UhJ9DF89gOwVFis05nJ4zDudEHRySmJmoFvtE4dUd
         J+sQbqchI3OK+vU7k/qyJnr9rUfke9suqr0amzYusJfyz+4pXQuMiIswTetFQ2a9sw/8
         4+0t/2Tv0Bwr4ndqGJm8v761eCTCUAn1wptAsJECZAbIrzR3h1r/ddEbjZdXgURXWil5
         QgS+uJG00CztMoNUvQP23GX8AkyfSqBNtLHjKTvuTc/CfbzEFQCrBJ5qsQy9y3kCgUJG
         iz5A==
X-Gm-Message-State: AOAM531yKWWWjW321yBRqDiAzlKT5a4hEndN0FmoEgYx6HKlNU9opnnv
	SBvDUaty+ZlPzOPHE+pUe88=
X-Google-Smtp-Source: ABdhPJykp8KAFUNIbIwEw/GIQ7EGH3NGgA4YjQBdHUui2js2ruXBNlmhmzzm6WtkMdhIZhLmPPPH4g==
X-Received: by 2002:a63:3681:: with SMTP id d123mr2703904pga.317.1596183468220;
        Fri, 31 Jul 2020 01:17:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:80d:: with SMTP id m13ls2826746pfk.2.gmail; Fri, 31
 Jul 2020 01:17:47 -0700 (PDT)
X-Received: by 2002:a62:1951:: with SMTP id 78mr2695994pfz.137.1596183467788;
        Fri, 31 Jul 2020 01:17:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183467; cv=none;
        d=google.com; s=arc-20160816;
        b=i6b5t9c1QZUq1edvuADhDNwBIIPiGAxYAkP8I1bgVHozkEIs9gqvEtJJXG0K+ksyce
         zI8iRZOBLDpw30eihRZsKwT1gJ52oFS6/jjz2565KsqT5FwQxgeXy+WvawtVNrogPMZU
         nfvemWZgGZWvR6J02AjlJspRChd8Nv6sSGMkC73oVttjr168FRY3EYYsSI9ZcRR/88ut
         7XGSj5TKSoFHrWXRONP2K9y/Bi89nXkHtZ3voww26vD8wqn0c1wA6+FckH1q7zyrvymT
         Fe0rUkKx39p0DWGEyG6nZtOZykkMEobiHvmGv3NiUpllU+L8tXQTZdTlUgA62dYZ+IfJ
         DGPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2Hs8pR7aozKTxu1D5WCBxSVPuPyLLXKSlzcEz3zNnOs=;
        b=L3ovTZqawgt6QkN5GD/E4IJ0HAY9ixWyzZ2+BTtT+pz7XLxMbFusHhrADTcqpP0klz
         iOyLVytjrZYQXnSdbAiHwXrfr4NcCwpneqKVaTggTs0fNGyGlEovR1qKI3oXjsvCmRfE
         fFVO8dyN124jmzYMN4I4bjhx1fS9k/xk5pXHFbNaoV+fu2nkEBegmdOvk0QarW3+KLMg
         kxT2KmQXFpJP8VAxh26SdVzh2onQbIwtiQa71qhlU6C3bUjRw/wA8mPQH4JfI5N/rDNq
         V4PulpUSDYssgeoKOgpKncYRYc79R236Vrqv7/MMaMOth6B6KjD3bF44oC/2M7+oMkJk
         c7Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SQCAbfAY;
       spf=pass (google.com: domain of 3qtmjxwukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qtMjXwUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id w2si343204plq.3.2020.07.31.01.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qtmjxwukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id 3so20404016qkv.13
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:47 -0700 (PDT)
X-Received: by 2002:a0c:f081:: with SMTP id g1mr2932894qvk.219.1596183466896;
 Fri, 31 Jul 2020 01:17:46 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:23 +0200
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
Message-Id: <20200731081723.2181297-6-elver@google.com>
Mime-Version: 1.0
References: <20200731081723.2181297-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 5/5] kcsan: Use pr_fmt for consistency
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SQCAbfAY;       spf=pass
 (google.com: domain of 3qtmjxwukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qtMjXwUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the same pr_fmt throughout for consistency. [ The only exception is
report.c, where the format must be kept precisely as-is. ]

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c  | 8 +++++---
 kernel/kcsan/selftest.c | 8 +++++---
 2 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index de1da1b01aa4..6c4914fa2fad 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -1,5 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#define pr_fmt(fmt) "kcsan: " fmt
+
 #include <linux/atomic.h>
 #include <linux/bsearch.h>
 #include <linux/bug.h>
@@ -80,7 +82,7 @@ static noinline void microbenchmark(unsigned long iters)
 	 */
 	WRITE_ONCE(kcsan_enabled, false);
 
-	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
+	pr_info("%s begin | iters: %lu\n", __func__, iters);
 
 	cycles = get_cycles();
 	while (iters--) {
@@ -91,7 +93,7 @@ static noinline void microbenchmark(unsigned long iters)
 	}
 	cycles = get_cycles() - cycles;
 
-	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
+	pr_info("%s end   | cycles: %llu\n", __func__, cycles);
 
 	WRITE_ONCE(kcsan_enabled, was_enabled);
 	/* restore context */
@@ -154,7 +156,7 @@ static ssize_t insert_report_filterlist(const char *func)
 	ssize_t ret = 0;
 
 	if (!addr) {
-		pr_err("KCSAN: could not find function: '%s'\n", func);
+		pr_err("could not find function: '%s'\n", func);
 		return -ENOENT;
 	}
 
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index d26a052d3383..d98bc208d06d 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -1,5 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#define pr_fmt(fmt) "kcsan: " fmt
+
 #include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/printk.h>
@@ -116,16 +118,16 @@ static int __init kcsan_selftest(void)
 		if (do_test())                                                 \
 			++passed;                                              \
 		else                                                           \
-			pr_err("KCSAN selftest: " #do_test " failed");         \
+			pr_err("selftest: " #do_test " failed");               \
 	} while (0)
 
 	RUN_TEST(test_requires);
 	RUN_TEST(test_encode_decode);
 	RUN_TEST(test_matching_access);
 
-	pr_info("KCSAN selftest: %d/%d tests passed\n", passed, total);
+	pr_info("selftest: %d/%d tests passed\n", passed, total);
 	if (passed != total)
-		panic("KCSAN selftests failed");
+		panic("selftests failed");
 	return 0;
 }
 postcore_initcall(kcsan_selftest);
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-6-elver%40google.com.
