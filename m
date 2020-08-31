Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AA0332580A9
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:10 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id b18sf5757575ilh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=CmhiU7NY0ucaPjX6hzcFqS8hhrwcfgZ6oNbXIR4wZD8Prw+c6VcDnR69Pw2WpBRZbW
         PMdhGlCatKJhEZHsGpTpsKuVh9mvQBTQeNQn8VpJJaR7bdjrK0OGbe6jsjx61+tsKqHq
         TI56R9ThgeEY/UzRdFU7fd0siOnIhvLkOF3rTGc/9HTH++YFQA0qsgZMv8Ayw857Ki3j
         mwvOc1I0VkShBCdM9NSD0w+P/RrLkGRV4UVb29nj0gGSp7zQUIgOk/M07rEboGIwrCPp
         PCf/SFYu8UnQsDRl4Xe/Vo6nmyVdy2sXZ4DiJFxKrAX8ds/PGyAignkWX16PK9ZSHObN
         d9ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=pbAE4ALlSdrKGbMjJno5IMf8xkWb6Fswo58gcoJDdCA=;
        b=evpSFdV/YrV3NjEy+p/wKkRAeSN1Ds4C0KUZHa0q+zYhESeaXIAT7h5zongq/Efauq
         Fm56A67oF+ywFk/wCOstxhaSnFa+yzMO5NwCOdl092RHLoug8LP4rtIlobBaL7Os+I63
         xWh2nUy6CVk29oyilvXFP+HjlhtSRsHHjwigji2Ph03n3lv6jTOKisztHZy58bZUduAH
         CZcN/DmqoA0XtN7Keai3psTu21Wx5HtAnGtI8f9pe07czhg+WmMkCzKCfZYTdmloqt9j
         PB1ysxxcX/ocWTpMX+EozpjgbgpwlHHdrrBejGvofU4x2BIGajMO0ESstZ5u4jieQOwE
         Eiow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CcS1arZW;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbAE4ALlSdrKGbMjJno5IMf8xkWb6Fswo58gcoJDdCA=;
        b=maVbyThF4TAc1jecASsXXG96tC3SkfgUCBiXf0akqcLypR5tSaXyto1ffEr3K6w86N
         pMEoeeVQD+C4SqTBWotWqEX11GUB4n2I/tbMSBnQWPK2NkF9iazAW/jojHIt+RCwVf/q
         nA9C4dgy4S4yB4H9lZWqgHvYuAvexH9gCDpMkIS7rM9eEylL8nfFJqGysuIP7hU6iSoT
         JTJqzYy/eOMY2bSQuYx/RaW/HUK3mUij5XbH8ox2PWhmEN7bIgWnNiLaV78/ed4mFQO7
         Z5HdPYM543eIpbUQZNQx8pDWO8pFO4tCI4Bf+zGEqJATuCUIcbXA+oFUE0FlL7kbb6oH
         rChQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbAE4ALlSdrKGbMjJno5IMf8xkWb6Fswo58gcoJDdCA=;
        b=f5QR83Ayq4JEhnPfk/glcSMEFVgwp7vAf/D6mngTgTmORRKKTGKVlUXVnGmnwiCgfS
         fzjSnqU/D7rQhmntvDbMwDRXqZu+LEIsLCw1ch7x0EDdi3l1U2JlUsA+8hd7Ls6mpTDs
         oosdR4DfkfxYPrWYkmffBoco2X4lZ6CxUGSeLuqUMCqwkEHrcN94qnHG9gPbvS86FQ1O
         9tNxzfjv6T1PQGzXs5ShrzdFFuix58G8Exd/glaM9dYX5Dm0H1kM0muu9ofAUFtAaUTo
         ipXOqYeqI0VdbuBP96sKGbMlqd76QLDU/if6S7ZW49i9bQrzD97dhZyM+g3Zh1XXvXSD
         hXXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YtzF40csm5kOQvutw7CERAcyrS11X7XE5xnfkQLG7JOzz2YjL
	OyeuuNK60DetApClI20dEFk=
X-Google-Smtp-Source: ABdhPJz6t3TBlw0lHE4ILiV9k/HGIOfI46se1uyNta3YcoSF7RA9DrmCMssmzPtUrQHws1+27/xIVQ==
X-Received: by 2002:a02:3f2d:: with SMTP id d45mr2438085jaa.120.1598897889575;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8bc4:: with SMTP id i187ls533739ild.2.gmail; Mon, 31 Aug
 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:a92:248:: with SMTP id 69mr2418503ilc.236.1598897889313;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=q59ww5PnB0ugvVa7mYWbkFK8kTfMF6W4or4ZorMM9/T2xuHNrfpsBtuRsBRE8GYhIK
         5o3m3Pj2jVBQfvCm+5fJU7OtZ41r2NyHctTluvjsg66jCknazEP/sn96AebBpM70cu9I
         E8f9PDJSR6p+DtA1X3Nh6bV1AWRGZyElaUH8XjO3TtAHNbYrpBKdnK4tLFyrVtIh5NLU
         hquiPnkcWs4BXqjE10en3Ohhu/46kUXvr9zQucbrIso9YSapL28oMPZCQzEFVapccp1d
         KHFufFpZ2qhfqinG71FlK6IZFZz/Q7zhMhdqldauQNyNqYfJzTvVpQfWQSZX6ZFsRNFl
         X3uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=GwTeZyFKExH0LZq7fEOm2eVC9FCBFQh473FVBKs+Avk=;
        b=ymFZe8ZymFoTAUcYHmjAXNxTqI6n50pFiYU6uWr5bwrhA4gTcl0GHEJ5+DK3UEN5kj
         FcEiqWGTFaGjr1fHG6syi92oIW0tjcr+rqQHvkPmGjPl+hDijWwhB2wc2k6hd9y+ifp7
         Vox8hjStwRrx1lyczMK++TEER2m5uKKBb3V+DPH3yOWy8aFvSyBhEk0lttE8p/LXQUH9
         K/LIJgHlfvg0qilxNWnTWPMm3RbBnSoyBY4IQ8cKCVjfdEWALMmK2pSFgQ5mZt1oR6Xk
         sSh/2jKWI6VoXHLIARckK+B2pKDmQhXZ1pbmtqkLXIDtmcTN6H5JySSQqZdHiA1T4Pky
         HR7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CcS1arZW;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j127si434999iof.4.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B85A921532;
	Mon, 31 Aug 2020 18:18:08 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 16/19] kcsan: Use pr_fmt for consistency
Date: Mon, 31 Aug 2020 11:18:02 -0700
Message-Id: <20200831181805.1833-16-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CcS1arZW;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Use the same pr_fmt throughout for consistency. [ The only exception is
report.c, where the format must be kept precisely as-is. ]

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c  | 8 +++++---
 kernel/kcsan/selftest.c | 8 +++++---
 2 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index de1da1b01..6c4914f 100644
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
index d26a052..d98bc20 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-16-paulmck%40kernel.org.
